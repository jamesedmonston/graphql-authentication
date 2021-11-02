<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\events\ExecuteGqlQueryEvent;
use craft\events\RegisterGqlMutationsEvent;
use craft\helpers\DateTimeHelper;
use craft\helpers\UrlHelper;
use craft\models\GqlSchema;
use craft\records\GqlToken as RecordsGqlToken;
use craft\services\Elements;
use craft\services\Gql;
use craft\services\Users;
use DateTime;
use DateTimeImmutable;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use InvalidArgumentException;
use jamesedmonston\graphqlauthentication\elements\RefreshToken;
use jamesedmonston\graphqlauthentication\events\JwtCreateEvent;
use jamesedmonston\graphqlauthentication\events\JwtValidateEvent;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use yii\base\Event;

class TokenService extends Component
{
    /**
     * @event JwtCreateEvent The event that is triggered before creating a JWT.
     *
     * Plugins get a chance to add additional claims to the JWT.
     *
     * ---
     * ```php
     * use jamesedmonston\graphqlauthentication\events\JwtCreateEvent;
     * use jamesedmonston\graphqlauthentication\services\TokenService;
     * use yii\base\Event;
     *
     * Event::on(
     *     TokenService::class,
     *     TokenService::EVENT_BEFORE_CREATE_JWT,
     *     function(JwtCreateEvent $event) {
     *         $builder = $event->builder;
     *         $user = $event->user;
     *         $builder->withClaim('customClaim', 'customValue');
     *     }
     * );
     * ```
     */
    const EVENT_BEFORE_CREATE_JWT = 'beforeCreateJwt';

    /**
     * @event JwtValidateEvent The event that is triggered before validating a JWT.
     *
     * Plugins get a chance to add additional validators to the JWT verification.
     *
     * ---
     * ```php
     * use jamesedmonston\graphqlauthentication\events\JwtValidateEvent;
     * use jamesedmonston\graphqlauthentication\services\TokenService;
     * use Lcobucci\JWT\Validation\Constraint\IssuedBy;
     * use yii\base\Event;
     *
     * Event::on(
     *     TokenService::class,
     *     TokenService::EVENT_BEFORE_VALIDATE_JWT,
     *     function(JwtValidateEvent $event) {
     *         $config = $event->config;
     *         $validator = new IssuedBy('Custom Validator');
     *         $config->setValidationConstraints($validator);
     *     }
     * );
     * ```
     */
    const EVENT_BEFORE_VALIDATE_JWT = 'beforeValidateJwt';

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );

        Event::on(
            Gql::class,
            Gql::EVENT_BEFORE_EXECUTE_GQL_QUERY,
            [$this, 'setActiveSchema']
        );
    }

    /**
     * Registers token management mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        $event->mutations['refreshToken'] = [
            'description' => "Refreshes a user's JWT. Checks for the occurrence of the `gql_refreshToken` cookie, and falls back to `refreshToken` argument.",
            'type' => Type::nonNull(Auth::getType()),
            'args' => [
                'refreshToken' => Type::string(),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $errorService) {
                $refreshToken = $_COOKIE['gql_refreshToken'] ?? $arguments['refreshToken'] ?? null;

                if (!$refreshToken) {
                    $errorService->throw($settings->invalidRefreshToken);
                }

                $this->_clearExpiredTokens();
                $refreshTokenElement = RefreshToken::find()->where(['[[token]]' => $refreshToken])->one();

                if (!$refreshTokenElement) {
                    $errorService->throw($settings->invalidRefreshToken);
                }

                /** @var Users */
                $usersService = Craft::$app->getUsers();
                $user = $usersService->getUserById($refreshTokenElement->userId);

                if (!$user) {
                    $errorService->throw($settings->userNotFound);
                }

                $schemaId = $refreshTokenElement->schemaId;

                if (!$schemaId) {
                    $errorService->throw($settings->invalidSchema);
                }

                /** @var Elements */
                $elementsService = Craft::$app->getElements();
                $elementsService->deleteElementById($refreshTokenElement->id);
                $token = $this->create($user, $schemaId);

                return GraphqlAuthentication::$userService->getResponseFields($user, $schemaId, $token);
            },
        ];

        $event->mutations['deleteRefreshToken'] = [
            'description' => 'Deletes authenticated user refresh token. Useful for logging out of current device. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [
                'refreshToken' => Type::string(),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $errorService) {
                if (!$this->getUserFromToken()) {
                    $errorService->throw($settings->tokenNotFound);
                }

                $refreshToken = $_COOKIE['gql_refreshToken'] ?? $arguments['refreshToken'] ?? null;

                if (!$refreshToken) {
                    $errorService->throw($settings->invalidRefreshToken);
                }

                GraphqlAuthentication::$tokenService->deleteRefreshToken($refreshToken);

                return true;
            },
        ];

        $event->mutations['deleteRefreshTokens'] = [
            'description' => 'Deletes all refresh tokens belonging to the authenticated user. Useful for logging out of all devices. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () use ($settings, $errorService) {
                if (!$user = $this->getUserFromToken()) {
                    $errorService->throw($settings->tokenNotFound);
                }

                GraphqlAuthentication::$tokenService->deleteRefreshTokens($user);

                return true;
            },
        ];
    }

    /**
     * Grabs the token from the `Authorization` header
     *
     * @return Token
     * @throws Error
     */
    public function getHeaderToken(): ?Token
    {
        $requestHeaders = Craft::$app->getRequest()->getHeaders();
        $authHeaders = $requestHeaders->get('authorization', [], false);

        if (empty($authHeaders)) {
            return null;
        }

        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        $token = null;

        foreach ($authHeaders as $authHeader) {
            $authValues = array_map('trim', explode(',', $authHeader));

            foreach ($authValues as $authValue) {
                if (!preg_match('/^JWT\s+(.+)$/i', $authValue, $matches)) {
                    continue;
                }

                if (!preg_match("/^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/", $matches[1])) {
                    $errorService->throw($settings->invalidHeader);
                }

                $token = $this->parseToken($matches[1]);
                break 2;
            }
        }

        if (!$token) {
            return null;
        }

        $this->_validateExpiry($token);
        return $token;
    }

    /**
     * Sets the active schema to the one encoded into the JWT
     *
     * @param ExecuteGqlQueryEvent $event
     */
    public function setActiveSchema(ExecuteGqlQueryEvent $event)
    {
        if (!$token = $this->getHeaderToken()) {
            return;
        }

        if (isset($event->variables['gql_cacheKey'])) {
            return;
        }

        /** @var Gql */
        $gqlService = Craft::$app->getGql();
        $schema = $this->getSchemaFromToken();

        // Insert user-specific cache key
        $event->variables['gql_cacheKey'] = 'user-' . $token->claims()->get('sub');

        $event->result = $gqlService->executeQuery(
            $schema,
            $event->query,
            $event->variables,
            $event->operationName,
            YII_DEBUG
        );
    }

    /**
     * Returns the schema linked to a token
     *
     * @return GqlSchema
     */
    public function getSchemaFromToken(): GqlSchema
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        if (!$token = $this->getHeaderToken()) {
            $errorService->throw($settings->invalidHeader);
        }

        /** @var Gql */
        $gqlService = Craft::$app->getGql();
        $schemaId = $token->claims()->get('schemaId') ?? null;

        // Temporary – remove this once users have had chance to update
        if (!$schemaId) {
            $schemaId = array_values(array_filter($gqlService->getSchemas(), function (GqlSchema $schema) use ($token) {
                return $schema->name === $token->claims()->get('schema');
            }))[0]->id ?? null;
        }

        if (!$schemaId) {
            $errorService->throw($settings->invalidHeader);
        }

        if (!$schema = $gqlService->getSchemaById($schemaId)) {
            $errorService->throw($settings->invalidHeader);
        }

        return $schema;
    }

    /**
     * Returns the user entity linked to a token
     *
     * @param Token|null $token
     * @return ?User
     * @throws Error
     */
    public function getUserFromToken(?Token $token = null): ?User
    {
        if (!$token) {
            $token = $this->getHeaderToken();
        }

        if (!$token) {
            GraphqlAuthentication::$errorService->throw(GraphqlAuthentication::$settings->invalidHeader);
        }

        $id = $token->claims()->get('sub');

        /** @var Users */
        $usersService = Craft::$app->getUsers();
        return $usersService->getUserById($id);
    }

    /**
     * Creates a JWT and refresh token. Sends refresh token as a cookie in response
     *
     * @param User $user
     * @param Int $schemaId
     * @return array
     * @throws Error
     */
    public function create(User $user, int $schemaId)
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        if (!$jwtSecretKey = GraphqlAuthentication::getInstance()->getSettingsData($settings->jwtSecretKey)) {
            $errorService->throw($settings->invalidJwtSecretKey);
        }

        $jwtConfig = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($jwtSecretKey)
        );

        /** @var Gql */
        $gqlService = Craft::$app->getGql();
        $now = new DateTimeImmutable();

        $builder = $jwtConfig->builder()
            ->issuedBy(Craft::$app->id ?? UrlHelper::cpUrl())
            ->issuedAt($now)
            ->expiresAt($now->modify($settings->jwtExpiration))
            ->relatedTo($user->id)
            ->withClaim('fullName', $user->fullName)
            ->withClaim('email', $user->email)
            ->withClaim('groups', array_column($user->getGroups(), 'name'))
            ->withClaim('schema', $gqlService->getSchemaById($schemaId)->name)
            ->withClaim('schemaId', $schemaId)
            ->withClaim('admin', $user->admin);

        $event = new JwtCreateEvent([
            'builder' => $builder,
            'user' => $user,
        ]);

        $this->trigger(self::EVENT_BEFORE_CREATE_JWT, $event);

        $jwt = $event->builder->getToken($jwtConfig->signer(), $jwtConfig->signingKey());
        $jwtExpiration = date_create(date('Y-m-d H:i:s'))->modify("+ {$settings->jwtExpiration}");
        $refreshToken = Craft::$app->getSecurity()->generateRandomString(32);
        $refreshTokenExpiration = date_create(date('Y-m-d H:i:s'))->modify("+ {$settings->jwtRefreshExpiration}");

        $refreshTokenElement = new RefreshToken([
            'token' => $refreshToken,
            'userId' => $user->id,
            'schemaId' => $schemaId,
            'expiryDate' => $refreshTokenExpiration->format('Y-m-d H:i:s'),
        ]);

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        if (!$elementsService->saveElement($refreshTokenElement)) {
            $errors = $refreshTokenElement->getErrors();
            $errorService->throw($errors[key($errors)][0], true);
        }

        $this->_setCookie('gql_refreshToken', $refreshToken, $settings->jwtRefreshExpiration);

        return [
            'jwt' => $jwt->toString(),
            'jwtExpiresAt' => $jwtExpiration->getTimestamp() * 1000,
            'refreshToken' => $refreshToken,
            'refreshTokenExpiresAt' => $refreshTokenExpiration->getTimestamp() * 1000,
        ];
    }

    /**
     * Deletes specific refresh token
     *
     * @param string $refreshToken
     */
    public function deleteRefreshToken(string $refreshToken)
    {
        $refreshToken = RefreshToken::find()->where(['[[token]]' => $refreshToken])->one();

        if (!$refreshToken) {
            GraphqlAuthentication::$errorService->throw(GraphqlAuthentication::$settings->invalidRefreshToken);
        }

        /** @var Elements */
        $elementsService = Craft::$app->getElements();
        $elementsService->deleteElementById($refreshToken->id);
    }

    /**
     * Deletes refresh tokens linked to user
     *
     * @param User $user
     */
    public function deleteRefreshTokens(User $user)
    {
        $refreshTokens = RefreshToken::find()->where(['[[userId]]' => $user->id])->all();

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        foreach ($refreshTokens as $refreshToken) {
            $elementsService->deleteElementById($refreshToken->id);
        }
    }

    /**
     * @param string $token
     * @return Token
     */
    public function parseToken(string $token): Token
    {
        /** @var GraphqlAuthentication $plugin Suppress NPE warning as this cannot happen here */
        $plugin = GraphqlAuthentication::getInstance();

        $settings = GraphqlAuthentication::$settings;

        $jwtSecretKey = $plugin->getSettingsData($settings->jwtSecretKey);

        $jwtConfig = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($jwtSecretKey)
        );

        $validator = new SignedWith(
            new Sha256(),
            InMemory::plainText($jwtSecretKey)
        );

        $jwtConfig->setValidationConstraints($validator);
        $constraints = $jwtConfig->validationConstraints();

        $errorService = GraphqlAuthentication::$errorService;

        try {
            $jwt = $jwtConfig->parser()->parse($token);
        } catch (InvalidArgumentException $e) {
            $errorService->throw($e->getMessage());
        }

        $event = new JwtValidateEvent([
            'config' => $jwtConfig,
        ]);

        $this->trigger(self::EVENT_BEFORE_VALIDATE_JWT, $event);

        try {
            $jwtConfig->validator()->assert($jwt, ...$constraints, ...$event->config->validationConstraints());
        } catch (RequiredConstraintsViolated $e) {
            $errorService->throw($settings->invalidHeader);
        }

        return $jwt;
    }

    // Protected Methods
    // =========================================================================

    /**
     * Sends a cookie with a response
     *
     * @param string $name
     * @param string $token
     * @param string $expiration
     * @return bool
     */
    protected function _setCookie(string $name, string $token, string $expiration = null): bool
    {
        $settings = GraphqlAuthentication::$settings;
        $expiry = 0;

        if ($expiration) {
            $expiry = strtotime((new DateTime())->modify("+ {$expiration}")->format('Y-m-d H:i:s'));
        }

        if (PHP_VERSION_ID < 70300) {
            return setcookie($name, $token, $expiry, "/; samesite={$settings->sameSitePolicy}", '', true, true);
        }

        return setcookie($name, $token, [
            'expires' => $expiry,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => $settings->sameSitePolicy,
        ]);
    }

    /**
     * Validates token expiry date
     *
     * @param Token $token
     * @throws Error
     */
    protected function _validateExpiry(Token $token)
    {
        /** @var DateTimeImmutable */
        $expiry = $token->claims()->get('exp');

        if (!DateTimeHelper::isInThePast($expiry->format('Y-m-d H:i:s'))) {
            return;
        }

        GraphqlAuthentication::$errorService->throw(GraphqlAuthentication::$settings->invalidHeader);
    }

    /**
     * Clears expired access and refresh tokens
     */
    protected function _clearExpiredTokens()
    {
        // Temporary – remove this once users have had chance to update
        $gqlTokens = RecordsGqlToken::find()->where('[[expiryDate]] <= CURRENT_TIMESTAMP')->andWhere("name LIKE '%user-%'")->all();

        /** @var Gql */
        $gqlService = Craft::$app->getGql();

        foreach ($gqlTokens as $gqlToken) {
            $gqlService->deleteTokenById($gqlToken->id);
        }

        $refreshTokens = RefreshToken::find()->where('[[expiryDate]] <= CURRENT_TIMESTAMP')->all();

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        foreach ($refreshTokens as $refreshToken) {
            $elementsService->deleteElementById($refreshToken->id, null, null, true);
        }
    }
}

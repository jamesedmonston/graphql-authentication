<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\controllers\GraphqlController;
use craft\elements\User;
use craft\helpers\StringHelper;
use craft\helpers\UrlHelper;
use craft\models\GqlToken;
use craft\services\Gql;
use DateTime;
use DateTimeImmutable;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\elements\RefreshToken;
use jamesedmonston\graphqlauthentication\events\JwtCreateEvent;
use jamesedmonston\graphqlauthentication\events\JwtValidateEvent;
use jamesedmonston\graphqlauthentication\gql\JWT;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Throwable;
use yii\base\Event;
use yii\base\InvalidArgumentException;
use yii\web\BadRequestHttpException;

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
     *
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
            GraphqlController::class,
            GraphqlController::EVENT_BEFORE_ACTION,
            [$this, 'rewriteJwtHeader']
        );

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    public function registerGqlMutations(Event $event)
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();

        if ($settings->tokenType === 'jwt') {
            $event->mutations['refreshToken'] = [
                'description' => "Refreshes a user's JWT. It first checks for the occurence of the automatically-set `gql_refreshToken` cookie, and falls back to the argument.",
                'type' => Type::nonNull(JWT::getType()),
                'args' => [
                    'refreshToken' => Type::string(),
                ],
                'resolve' => function ($source, array $arguments) use ($settings) {
                    $refreshToken = $_COOKIE['gql_refreshToken'] ?? $arguments['refreshToken'] ?? null;

                    if (!$refreshToken) {
                        throw new Error($settings->invalidRefreshToken);
                    }

                    $this->_clearExpiredTokens();
                    $refreshTokenElement = RefreshToken::find()->where(['token' => $refreshToken])->one();

                    if (!$refreshTokenElement) {
                        throw new Error($settings->invalidRefreshToken);
                    }

                    $user = Craft::$app->getUsers()->getUserById($refreshTokenElement->userId);

                    if (!$user) {
                        throw new Error($settings->userNotFound);
                    }

                    $schemaId = $refreshTokenElement->schemaId;

                    if (!$user) {
                        throw new Error($settings->invalidSchema);
                    }

                    Craft::$app->getElements()->deleteElementById($refreshTokenElement->id);
                    $token = $this->create($user, $schemaId);
                    return $token;
                },
            ];
        }
    }

    public function getHeaderToken(): GqlToken
    {
        $request = Craft::$app->getRequest();
        $requestHeaders = $request->getHeaders();
        $settings = GraphqlAuthentication::$plugin->getSettings();

        switch ($settings->tokenType) {
            case 'response':
                foreach ($requestHeaders->get('authorization', [], false) as $authHeader) {
                    $authValues = array_map('trim', explode(',', $authHeader));

                    foreach ($authValues as $authValue) {
                        if (preg_match('/^Bearer\s+(.+)$/i', $authValue, $matches)) {
                            try {
                                $token = Craft::$app->getGql()->getTokenByAccessToken($matches[1]);
                            } catch (InvalidArgumentException $e) {
                                throw new InvalidArgumentException($e);
                            }

                            if (!$token) {
                                throw new BadRequestHttpException($settings->invalidHeader);
                            }

                            break 2;
                        }
                    }
                }

                if (!isset($token)) {
                    throw new BadRequestHttpException($settings->invalidHeader);
                }

                $this->_validateExpiry($token);
                return $token;

            case 'cookie':
                try {
                    $token = Craft::$app->getGql()->getTokenByAccessToken($_COOKIE['gql_accessToken']);
                } catch (InvalidArgumentException $e) {
                    throw new InvalidArgumentException($e);
                }

                if (!isset($token)) {
                    throw new BadRequestHttpException($settings->invalidHeader);
                }

                $this->_validateExpiry($token);
                return $token;

            case 'jwt':
                foreach ($requestHeaders->get('authorization', [], false) as $authHeader) {
                    $authValues = array_map('trim', explode(',', $authHeader));

                    foreach ($authValues as $authValue) {
                        if (preg_match('/^Bearer\s+(.+)$/i', $authValue, $matches)) {
                            try {
                                $token = Craft::$app->getGql()->getTokenByAccessToken($matches[1]);
                            } catch (InvalidArgumentException $e) {
                                throw new InvalidArgumentException($e);
                            }

                            if (!$token) {
                                throw new BadRequestHttpException($settings->invalidHeader);
                            }

                            break 2;
                        }

                        if (preg_match('/^JWT\s+(.+)$/i', $authValue, $matches)) {
                            try {
                                $jwtConfig = Configuration::forSymmetricSigner(
                                    new Sha256(),
                                    InMemory::plainText($settings->jwtSecretKey)
                                );

                                $validator = new SignedWith(
                                    new Sha256(),
                                    InMemory::plainText($settings->jwtSecretKey)
                                );

                                $jwtConfig->setValidationConstraints($validator);
                                $constraints = $jwtConfig->validationConstraints();

                                $jwt = $jwtConfig->parser()->parse($matches[1]);

                                $event = new JwtValidateEvent([
                                    'config' => $jwtConfig,
                                ]);

                                $this->trigger(self::EVENT_BEFORE_VALIDATE_JWT, $event);

                                try {
                                    $jwtConfig->validator()->assert($jwt, ...$constraints, ...$event->config->validationConstraints());
                                } catch (RequiredConstraintsViolated $e) {
                                    throw new Error(json_encode($e->violations()));
                                }

                                $accessToken = $jwt->claims()->get('accessToken');
                                $token = Craft::$app->getGql()->getTokenByAccessToken($accessToken);
                            } catch (InvalidArgumentException $e) {
                                throw new InvalidArgumentException($e);
                            }

                            if (!$token) {
                                throw new BadRequestHttpException($settings->invalidHeader);
                            }

                            break 2;
                        }
                    }
                }

                if (!isset($token)) {
                    throw new BadRequestHttpException($settings->invalidHeader);
                }

                $this->_validateExpiry($token);
                return $token;
        }
    }

    public function rewriteJwtHeader()
    {
        if (GraphqlAuthentication::$plugin->getSettings()->tokenType !== 'jwt') {
            return;
        }

        $request = Craft::$app->getRequest();
        $requestHeaders = $request->getHeaders();

        try {
            if (GraphqlAuthentication::$plugin->getInstance()->restriction->shouldRestrictRequests()) {
                $token = $this->getHeaderToken();
                $requestHeaders->set('authorization', "Bearer {$token->accessToken}");
            }
        } catch (Throwable $e) {}
    }

    public function getUserFromToken(): User
    {
        return Craft::$app->getUsers()->getUserById($this->_extractUserId());
    }

    public function create(User $user, Int $schemaId)
    {
        $this->_clearExpiredTokens();

        $settings = GraphqlAuthentication::$plugin->getSettings();
        $accessToken = Craft::$app->getSecurity()->generateRandomString(32);
        $time = microtime(true);

        $fields = [
            'name' => "user-{$user->id}-{$time}",
            'accessToken' => $accessToken,
            'enabled' => true,
            'schemaId' => $schemaId,
        ];

        switch ($settings->tokenType) {
            case 'response':
            case 'cookie':
                if ($settings->expiration) {
                    $fields['expiryDate'] = (new DateTime())->modify("+ {$settings->expiration}");
                }
                break;

            case 'jwt':
                $fields['expiryDate'] = (new DateTime())->modify("+ {$settings->jwtExpiration}");
                break;

            default:
                break;
        }

        $token = new GqlToken($fields);

        if (!Craft::$app->getGql()->saveToken($token)) {
            throw new Error(json_encode($token->getErrors()));
        }

        if ($settings->tokenType !== 'jwt') {
            if ($settings->tokenType === 'cookie') {
                $this->_setCookie('gql_accessToken', $accessToken, $settings->expiration);
            }

            return $accessToken;
        }

        if (!$settings->jwtSecretKey) {
            throw new Error($settings->invalidJwtSecretKey);
        }

        $jwtConfig = Configuration::forSymmetricSigner(
            new Sha256(),
            InMemory::plainText($settings->jwtSecretKey)
        );

        $now = new DateTimeImmutable();

        $builder = $jwtConfig->builder()
            ->issuedBy(Craft::$app->id ?? UrlHelper::cpUrl())
            ->issuedAt($now)
            ->expiresAt($now->modify($settings->jwtExpiration))
            ->relatedTo($user->id)
            ->withClaim('fullName', $user->fullName)
            ->withClaim('email', $user->email)
            ->withClaim('groups', array_column($user->getGroups(), 'name'))
            ->withClaim('schema', $token->getSchema()->name)
            ->withClaim('admin', $user->admin)
            ->withClaim('accessToken', $accessToken);

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

        if (!Craft::$app->getElements()->saveElement($refreshTokenElement)) {
            throw new Error(json_encode($refreshTokenElement->getErrors()));
        }

        $this->_setCookie('gql_refreshToken', $refreshToken, $settings->jwtRefreshExpiration);

        return [
            'jwt' => $jwt->toString(),
            'jwtExpiresAt' => $jwtExpiration->getTimestamp(),
            'refreshToken' => $refreshToken,
            'refreshTokenExpiresAt' => $refreshTokenExpiration->getTimestamp(),
        ];
    }

    // Protected Methods
    // =========================================================================

    protected function _setCookie(string $name, string $token, $expiration = null): bool
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
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

    protected function _extractUserId(): string
    {
        $token = $this->getHeaderToken();
        return explode('-', $token->name)[1];
    }

    protected function _validateExpiry(GqlToken $token)
    {
        if (!$token->expiryDate) {
            return;
        }

        if (strtotime(date('Y-m-d H:i:s')) < strtotime($token->expiryDate->format('Y-m-d H:i:s'))) {
            return;
        }

        throw new BadRequestHttpException(GraphqlAuthentication::$plugin->getSettings()->invalidHeader);
    }

    protected function _clearExpiredTokens()
    {
        $now = time();

        $gql = Craft::$app->getGql();
        $gqlTokens = $gql->getTokens();

        foreach ($gqlTokens as $gqlToken) {
            if (!StringHelper::contains($gqlToken->name, 'user-')) {
                continue;
            }

            if (strtotime($gqlToken->expiryDate->format('Y-m-d H:i:s')) > $now) {
                continue;
            }

            $gql->deleteTokenById($gqlToken->id);
        }

        $elements = Craft::$app->getElements();
        $refreshTokens = RefreshToken::find()->all();

        foreach ($refreshTokens as $refreshToken) {
            if (strtotime(date_create($refreshToken->expiryDate)->format('Y-m-d H:i:s')) > $now) {
                continue;
            }

            $elements->deleteElementById($refreshToken->id);
        }
    }
}

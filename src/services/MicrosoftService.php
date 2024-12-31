<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Gql;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use TheNetworg\OAuth2\Client\Provider\Azure;
use TheNetworg\OAuth2\Client\Provider\AzureResourceOwner;
use Throwable;
use yii\base\Event;

class MicrosoftService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_QUERIES,
            [$this, 'registerGqlQueries']
        );

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    /**
     * Registers Login with Microsoft queries
     *
     * @param RegisterGqlQueriesEvent $event
     */
    public function registerGqlQueries(RegisterGqlQueriesEvent $event)
    {
        if (!GraphqlAuthentication::$tokenService->getHeaderToken()) {
            return;
        }

        if (!$this->_validateSettings()) {
            return;
        }

        $event->queries['microsoftOauthUrl'] = [
            'description' => 'Generates the Microsoft OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function() {
                $settings = GraphqlAuthentication::$settings;

                $provider = new Azure([
                    'clientId' => GraphqlAuthentication::getInstance()->getSettingsData($settings->microsoftAppId),
                    'clientSecret' => GraphqlAuthentication::getInstance()->getSettingsData($settings->microsoftAppSecret),
                    'redirectUri' => GraphqlAuthentication::getInstance()->getSettingsData($settings->microsoftRedirectUrl),
                ]);

                $state = Craft::$app->getSecurity()->generateRandomString();
                $sessionService = Craft::$app->getSession();
                $sessionService->set('state', $state);

                $url = $provider->getAuthorizationUrl([
                    'scope' => ['offline_access', 'profile', 'user', 'email'],
                    'state' => $state,
                ]);

                return $url;
            },
        ];
    }

    /**
     * Registers Login with Microsoft mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        if (!$this->_validateSettings()) {
            return;
        }

        switch (GraphqlAuthentication::$settings->permissionType) {
            case 'single':
                $event->mutations['microsoftSignIn'] = [
                    'description' => 'Authenticates a user using a Login with Microsoft token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'code' => Type::nonNull(Type::string()),
                        'state' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function($source, array $arguments) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                        }

                        $code = $arguments['code'];
                        $state = $arguments['state'];
                        $tokenUser = $this->_getUserFromToken($code, $state);

                        $user = GraphqlAuthentication::$socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                $userGroupsService = Craft::$app->getUserGroups();
                $userGroups = $userGroupsService->getAllGroups();

                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["microsoftSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Login with Microsoft token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'code' => Type::nonNull(Type::string()),
                            'state' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function($source, array $arguments) use ($userGroup) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                            $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                            }

                            $code = $arguments['code'];
                            $state = $arguments['state'];
                            $tokenUser = $this->_getUserFromToken($code, $state);

                            $user = GraphqlAuthentication::$socialService->authenticate($tokenUser, $schemaId, $userGroup->id);
                            return $user;
                        },
                    ];
                }
                break;
        }
    }

    // Protected Methods
    // =========================================================================

    /**
     * Ensures settings are set
     *
     * @return bool
     */
    protected function _validateSettings(): bool
    {
        $settings = GraphqlAuthentication::$settings;
        return (bool) $settings->microsoftAppId && (bool) $settings->microsoftAppSecret && (bool) $settings->microsoftRedirectUrl;
    }

    /**
     * Gets user details from Login with Microsoft token
     *
     * @param string $code
     * @param string $state
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $code, string $state): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        try {
            $provider = new Azure([
                'clientId' => GraphqlAuthentication::getInstance()->getSettingsData($settings->microsoftAppId),
                'clientSecret' => GraphqlAuthentication::getInstance()->getSettingsData($settings->microsoftAppSecret),
                'redirectUri' => GraphqlAuthentication::getInstance()->getSettingsData($settings->microsoftRedirectUrl),
            ]);

            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $code,
            ]);

            /** @var AzureResourceOwner $user */
            $user = $provider->getResourceOwner($accessToken);
            $email = $user->claim('email') ?? $user->claim('upn');

            if (!$email) {
                $errorService->throw($settings->emailNotInScope);
            }

            if ($settings->allowedMicrosoftDomains) {
                GraphqlAuthentication::$socialService->verifyEmailDomain(
                    $email,
                    $settings->allowedMicrosoftDomains,
                    $settings->microsoftEmailMismatch
                );
            }

            $firstName = $user->claim('given_name') ?? '';
            $lastName = $user->claim('family_name') ?? '';

            return compact(
                'email',
                'firstName',
                'lastName'
            );
        } catch (Throwable $e) {
            $errorService->throw($e->getMessage());
        }
    }
}

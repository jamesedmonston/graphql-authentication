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
use League\OAuth2\Client\Provider\Facebook;
use yii\base\Event;

class FacebookService extends Component
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
     * Registers Facebook Login queries
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

        $event->queries['facebookOauthUrl'] = [
            'description' => 'Generates the Facebook OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function() {
                $settings = GraphqlAuthentication::$settings;

                $client = new Facebook([
                    'clientId' => GraphqlAuthentication::getInstance()->getSettingsData($settings->facebookAppId),
                    'clientSecret' => GraphqlAuthentication::getInstance()->getSettingsData($settings->facebookAppSecret),
                    'redirectUri' => GraphqlAuthentication::getInstance()->getSettingsData($settings->facebookRedirectUrl),
                    'graphApiVersion' => 'v2.10',
                ]);

                $url = $client->getAuthorizationUrl(['scope' => ['email']]);
                return $url;
            },
        ];
    }

    /**
     * Registers Facebook Login mutations
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
                $event->mutations['facebookSignIn'] = [
                    'description' => 'Authenticates a user using a Facebook Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'code' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function($source, array $arguments) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                        }

                        $code = $arguments['code'];
                        $tokenUser = $this->_getUserFromToken($code);

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

                    $event->mutations["facebookSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Facebook Sign-In token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'code' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function($source, array $arguments) use ($userGroup) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                            $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                            }

                            $code = $arguments['code'];
                            $tokenUser = $this->_getUserFromToken($code);

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
        return (bool) $settings->facebookAppId && (bool) $settings->facebookAppSecret && (bool) $settings->facebookRedirectUrl;
    }

    /**
     * Gets user details from Facebook Login token
     *
     * @param string $code
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $code): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        $client = new Facebook([
            'clientId' => GraphqlAuthentication::getInstance()->getSettingsData($settings->facebookAppId),
            'clientSecret' => GraphqlAuthentication::getInstance()->getSettingsData($settings->facebookAppSecret),
            'redirectUri' => GraphqlAuthentication::getInstance()->getSettingsData($settings->facebookRedirectUrl),
            'graphApiVersion' => 'v2.10',
        ]);

        $accessToken = $client->getAccessToken('authorization_code', [
            'code' => $code,
        ]);

        $user = $client->getResourceOwner($accessToken);
        $email = $user->getEmail();

        if (!$email) {
            $errorService->throw($settings->emailNotInScope);
        }

        if ($settings->allowedFacebookDomains) {
            GraphqlAuthentication::$socialService->verifyEmailDomain(
                $email,
                $settings->allowedFacebookDomains,
                $settings->facebookEmailMismatch
            );
        }

        $fullName = $user->getName() ?? '';

        return compact(
            'email',
            'fullName'
        );
    }
}

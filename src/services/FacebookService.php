<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\services\Gql;
use Facebook\Facebook;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class FacebookService extends Component
{
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
        if (!$this->_validateSettings()) {
            return;
        }

        $event->queries['facebookOauthUrl'] = [
            'description' => 'Generates the Facebook OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function () {
                $settings = GraphqlAuthentication::$plugin->getSettings();

                $client = new Facebook([
                    'app_id' => GraphqlAuthentication::$plugin->getSettingsData($settings->facebookAppId),
                    'app_secret' => GraphqlAuthentication::$plugin->getSettingsData($settings->facebookAppSecret),
                ]);

                $url = $client->getRedirectLoginHelper()->getLoginUrl(
                    GraphqlAuthentication::$plugin->getSettingsData($settings->facebookRedirectUrl),
                    ['email']
                );

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

        $userGroups = Craft::$app->getUserGroups()->getAllGroups();
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $socialService = GraphqlAuthentication::$plugin->getInstance()->social;
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;

        switch ($settings->permissionType) {
            case 'single':
                $event->mutations['facebookSignIn'] = [
                    'description' => 'Authenticates a user using a Facebook Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'code' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService) {
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            $errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $code = $arguments['code'];
                        $tokenUser = $this->_getUserFromToken($code);

                        $user = $socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["facebookSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Facebook Sign-In token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'code' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService, $userGroup) {
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                $errorService->throw($settings->invalidSchema, 'INVALID');
                            }

                            $code = $arguments['code'];
                            $tokenUser = $this->_getUserFromToken($code);

                            $user = $socialService->authenticate($tokenUser, $schemaId, $userGroup->id);
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
        $settings = GraphqlAuthentication::$plugin->getSettings();
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
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;

        $client = new Facebook([
            'app_id' => GraphqlAuthentication::$plugin->getSettingsData($settings->facebookAppId),
            'app_secret' => GraphqlAuthentication::$plugin->getSettingsData($settings->facebookAppSecret),
        ]);

        $redirectUrl = GraphqlAuthentication::$plugin->getSettingsData($settings->facebookRedirectUrl);
        $accessToken = $client->getOAuth2Client()->getAccessTokenFromCode($code, $redirectUrl);

        if (!$accessToken) {
            $errorService->throw($settings->invalidOauthToken, 'INVALID');
        }

        $user = $client->get('/me?fields=id,name,email', $accessToken->getValue())->getGraphUser();
        $email = $user['email'];

        if (!$email || !isset($email)) {
            $errorService->throw($settings->emailNotInScope, 'INVALID');
        }

        if ($settings->allowedFacebookDomains) {
            GraphqlAuthentication::$plugin->getInstance()->social->verifyEmailDomain(
                $email,
                $settings->allowedFacebookDomains,
                $settings->facebookEmailMismatch
            );
        }

        $name = explode(' ', $user['name'] ?? '', 1);
        $firstName = $name[0] ?? '';
        $lastName = $name[1] ?? '';

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

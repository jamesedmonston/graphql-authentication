<?php

namespace jamesedmonston\graphqlauthentication\services;

use Abraham\TwitterOAuth\TwitterOAuth;
use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Gql;
use craft\services\UserGroups;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class TwitterService extends Component
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
     * Registers Login with Twitter queries
     *
     * @param RegisterGqlQueriesEvent $event
     */
    public function registerGqlQueries(RegisterGqlQueriesEvent $event)
    {
        if (!$this->_validateSettings()) {
            return;
        }

        $event->queries['twitterOauthUrl'] = [
            'description' => 'Generates the Twitter OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function() {
                $settings = GraphqlAuthentication::$settings;

                $client = new TwitterOAuth(
                    GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterApiKey),
                    GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterApiKeySecret)
                );

                $requestToken = $client->oauth(
                    'oauth/request_token',
                    [
                        'oauth_callback' =>
                        GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterRedirectUrl),
                    ]
                );

                $oauthToken = $requestToken['oauth_token'];
                $oauthTokenSecret = $requestToken['oauth_token_secret'];

                $sessionService = Craft::$app->getSession();
                $sessionService->set('oauthToken', $oauthToken);
                $sessionService->set('oauthTokenSecret', $oauthTokenSecret);

                $url = $client->url('oauth/authorize', ['oauth_token' => $oauthToken]);
                return $url;
            },
        ];
    }

    /**
     * Registers Login with Twitter mutations
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
                $event->mutations['twitterSignIn'] = [
                    'description' => 'Authenticates a user using a Twitter Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'oauthToken' => Type::nonNull(Type::string()),
                        'oauthVerifier' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function($source, array $arguments) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                        }

                        $oauthToken = $arguments['oauthToken'];
                        $oauthVerifier = $arguments['oauthVerifier'];
                        $tokenUser = $this->_getUserFromToken($oauthToken, $oauthVerifier);

                        $user = GraphqlAuthentication::$socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                /** @var UserGroups */
                $userGroupsService = Craft::$app->getUserGroups();
                $userGroups = $userGroupsService->getAllGroups();

                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["twitterSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Twitter Sign-In token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'oauthToken' => Type::nonNull(Type::string()),
                            'oauthVerifier' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function($source, array $arguments) use ($userGroup) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                            $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                            }

                            $oauthToken = $arguments['oauthToken'];
                            $oauthVerifier = $arguments['oauthVerifier'];
                            $tokenUser = $this->_getUserFromToken($oauthToken, $oauthVerifier);

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
        return (bool) $settings->twitterApiKey && (bool) $settings->twitterApiKeySecret && (bool) $settings->twitterRedirectUrl;
    }

    /**
     * Gets user details from Login with Twitter token
     *
     * @param string $oauthToken
     * @param string $oauthVerifier
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $oauthToken, string $oauthVerifier): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        $sessionService = Craft::$app->getSession();
        $sessionOauthToken = $sessionService->get('oauthToken');
        $sessionOauthTokenSecret = $sessionService->get('oauthTokenSecret');

        if ($oauthToken !== $sessionOauthToken) {
            $errorService->throw($settings->invalidOauthToken);
        }

        $client = new TwitterOAuth(
            GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterApiKey),
            GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterApiKeySecret),
            $sessionOauthToken,
            $sessionOauthTokenSecret
        );

        $accessToken = $client->oauth('oauth/access_token', ['oauth_verifier' => $oauthVerifier]);

        $client = new TwitterOAuth(
            GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterApiKey),
            GraphqlAuthentication::getInstance()->getSettingsData($settings->twitterApiKeySecret),
            $accessToken['oauth_token'],
            $accessToken['oauth_token_secret']
        );

        $user = $client->get('account/verify_credentials', ['include_email' => true, 'entities' => false, 'skip_status' => true]);
        /** @phpstan-ignore-next-line */
        $email = $user->email;

        if (!$email || !isset($email)) {
            $errorService->throw($settings->emailNotInScope);
        }

        if ($settings->allowedTwitterDomains) {
            GraphqlAuthentication::$socialService->verifyEmailDomain(
                $email,
                $settings->allowedTwitterDomains,
                $settings->twitterEmailMismatch
            );
        }

        $name = explode(' ', $user->name ?? '', 1);
        $firstName = $name[0] ?? '';
        $lastName = $name[1] ?? '';

        $sessionService->remove('oauthToken');
        $sessionService->remove('oauthTokenSecret');

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

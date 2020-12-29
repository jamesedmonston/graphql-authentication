<?php

namespace jamesedmonston\graphqlauthentication\services;

use Abraham\TwitterOAuth\TwitterOAuth;
use Craft;
use craft\base\Component;
use craft\services\Gql;
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

    public function registerGqlQueries(Event $event)
    {
        if (!$this->_validateSettings()) {
            return;
        }

        $event->queries['twitterOauthUrl'] = [
            'description' => 'Generates the Twitter OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function () {
                $settings = GraphqlAuthentication::$plugin->getSettings();
                $client = new TwitterOAuth($settings->twitterApiKey, $settings->twitterApiKeySecret);
                $requestToken = $client->oauth('oauth/request_token', ['oauth_callback' => $settings->twitterRedirectUrl]);

                $oauthToken = $requestToken['oauth_token'];
                $oauthTokenSecret = $requestToken['oauth_token_secret'];

                $session = Craft::$app->getSession();
                $session->set('oauthToken', $oauthToken);
                $session->set('oauthTokenSecret', $oauthTokenSecret);

                $url = $client->url('oauth/authorize', ['oauth_token' => $oauthToken]);
                return $url;
            },
        ];
    }

    public function registerGqlMutations(Event $event)
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
                $event->mutations['twitterSignIn'] = [
                    'description' => 'Authenticates a user using a Twitter Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'oauthToken' => Type::nonNull(Type::string()),
                        'oauthVerifier' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService) {
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            $errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $oauthToken = $arguments['oauthToken'];
                        $oauthVerifier = $arguments['oauthVerifier'];
                        $tokenUser = $this->_getUserFromToken($oauthToken, $oauthVerifier);

                        $user = $socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["twitterSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Twitter Sign-In token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'oauthToken' => Type::nonNull(Type::string()),
                            'oauthVerifier' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService, $userGroup) {
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                $errorService->throw($settings->invalidSchema, 'INVALID');
                            }

                            $oauthToken = $arguments['oauthToken'];
                            $oauthVerifier = $arguments['oauthVerifier'];
                            $tokenUser = $this->_getUserFromToken($oauthToken, $oauthVerifier);

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

    protected function _validateSettings(): bool
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        return (bool) $settings->twitterApiKey && $settings->twitterApiKeySecret && $settings->twitterRedirectUrl;
    }

    protected function _getUserFromToken(string $oauthToken, string $oauthVerifier): array
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;
        $session = Craft::$app->getSession();
        $sessionOauthToken = $session->get('oauthToken');
        $sessionOauthTokenSecret = $session->get('oauthTokenSecret');

        if ($oauthToken !== $sessionOauthToken) {
            $errorService->throw($settings->invalidOauthToken, 'INVALID');
        }

        $client = new TwitterOAuth($settings->twitterApiKey, $settings->twitterApiKeySecret, $sessionOauthToken, $sessionOauthTokenSecret);
        $accessToken = $client->oauth('oauth/access_token', ['oauth_verifier' => $oauthVerifier]);

        $client = new TwitterOAuth($settings->twitterApiKey, $settings->twitterApiKeySecret, $accessToken['oauth_token'], $accessToken['oauth_token_secret']);
        $user = $client->get('account/verify_credentials', ['include_email' => true, 'entities' => false, 'skip_status' => true]);

        $email = $user->email;

        if (!$email || !isset($email)) {
            $errorService->throw($settings->emailNotInScope, 'INVALID');
        }

        if ($settings->allowedTwitterDomains) {
            GraphqlAuthentication::$plugin->getInstance()->social->verifyEmailDomain(
                $email,
                $settings->allowedTwitterDomains,
                $settings->twitterEmailMismatch
            );
        }

        $name = explode(' ', $user->name ?? '', 1);
        $firstName = $name[0] ?? '';
        $lastName = $name[1] ?? '';

        $session->remove('oauthToken');
        $session->remove('oauthTokenSecret');

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

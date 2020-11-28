<?php

namespace jamesedmonston\graphqlauthentication\services;

use Abraham\TwitterOAuth\TwitterOAuth;
use Craft;
use craft\base\Component;
use craft\services\Gql;
use Facebook\Facebook;
use Google_Client;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class SocialService extends Component
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
        $settings = GraphqlAuthentication::$plugin->getSettings();

        if ($this->_validateFacebookSettings()) {
            $event->queries['facebookOauthUrl'] = [
                'description' => 'Generates the Facebook OAuth URL for allowing users to authenticate.',
                'type' => Type::nonNull(Type::string()),
                'args' => [],
                'resolve' => function () use ($settings) {
                    $client = new Facebook([
                        'app_id' => $settings->facebookAppId,
                        'app_secret' => $settings->facebookAppSecret,
                    ]);

                    $url = $client->getRedirectLoginHelper()->getLoginUrl($settings->facebookRedirectUrl, ['email']);
                    return $url;
                },
            ];
        }

        if ($this->_validateTwitterSettings()) {
            $event->queries['twitterOauthUrl'] = [
                'description' => 'Generates the Twitter OAuth URL for allowing users to authenticate.',
                'type' => Type::nonNull(Type::string()),
                'args' => [],
                'resolve' => function () use ($settings) {
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
    }

    public function registerGqlMutations(Event $event)
    {
        $users = Craft::$app->getUsers();
        $gql = Craft::$app->getGql();
        $userGroups = Craft::$app->getUserGroups()->getAllGroups();
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $userService = GraphqlAuthentication::$plugin->getInstance()->user;
        $tokenService = GraphqlAuthentication::$plugin->getInstance()->token;

        if ($settings->permissionType === 'single' && $settings->googleClientId) {
            $event->mutations['googleSignIn'] = [
                'description' => 'Authenticates a user using a Google Sign-In ID token. Returns user and token.',
                'type' => Type::nonNull(Auth::getType()),
                'args' => [
                    'idToken' => Type::nonNull(Type::string()),
                ],
                'resolve' => function ($source, array $arguments) use ($users, $gql, $settings, $userService, $tokenService) {
                    $schemaId = $settings->schemaId;

                    if (!$schemaId) {
                        throw new Error($settings->invalidSchema);
                    }

                    $idToken = $arguments['idToken'];
                    $tokenUser = $this->_getUserFromGoogleToken($idToken);
                    $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

                    if (!$user) {
                        if (!$settings->allowRegistration) {
                            throw new Error($settings->userNotFound);
                        }

                        $user = $userService->create([
                            'email' => $tokenUser['email'],
                            'password' => '',
                            'firstName' => $tokenUser['firstName'],
                            'lastName' => $tokenUser['lastName'],
                        ], $settings->userGroup);
                    }

                    $token = $tokenService->create($user, $schemaId);

                    return [
                        'accessToken' => $token,
                        'user' => $user,
                        'schema' => $gql->getSchemaById($schemaId)->name,
                    ];
                },
            ];
        }

        if ($settings->permissionType === 'multiple' && $settings->googleClientId) {
            foreach ($userGroups as $userGroup) {
                $handle = ucfirst($userGroup->handle);

                $event->mutations["googleSignIn{$handle}"] = [
                    'description' => "Authenticates a {$userGroup->name} using a Google Sign-In ID token. Returns user and token.",
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'idToken' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($users, $gql, $settings, $userService, $tokenService, $userGroup) {
                        $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                        if (!$schemaId) {
                            throw new Error($settings->invalidSchema);
                        }

                        $idToken = $arguments['idToken'];
                        $tokenUser = $this->_getUserFromGoogleToken($idToken);
                        $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

                        if (!$user) {
                            if (!($settings->granularSchemas["group-{$userGroup->id}"]['allowRegistration'] ?? false)) {
                                throw new Error($settings->invalidSchema);
                            }

                            $user = $userService->create([
                                'email' => $tokenUser['email'],
                                'password' => '',
                                'firstName' => $tokenUser['firstName'],
                                'lastName' => $tokenUser['lastName'],
                            ], $userGroup->id);
                        }

                        $token = $tokenService->create($user, $schemaId);

                        return [
                            'accessToken' => $token,
                            'user' => $user,
                            'schema' => $gql->getSchemaById($schemaId)->name,
                        ];
                    },
                ];
            }
        }

        if ($settings->permissionType === 'single' && $this->_validateFacebookSettings()) {
            $event->mutations['facebookSignIn'] = [
                'description' => 'Authenticates a user using a Facebook Sign-In token. Returns user and token.',
                'type' => Type::nonNull(Auth::getType()),
                'args' => [
                    'code' => Type::nonNull(Type::string()),
                ],
                'resolve' => function ($source, array $arguments) use ($users, $gql, $settings, $userService, $tokenService) {
                    $schemaId = $settings->schemaId;

                    if (!$schemaId) {
                        throw new Error($settings->invalidSchema);
                    }

                    $code = $arguments['code'];
                    $tokenUser = $this->_getUserFromFacebookToken($code);
                    $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

                    if (!$user) {
                        if (!$settings->allowRegistration) {
                            throw new Error($settings->userNotFound);
                        }

                        $user = $userService->create([
                            'email' => $tokenUser['email'],
                            'password' => '',
                            'firstName' => $tokenUser['firstName'],
                            'lastName' => $tokenUser['lastName'],
                        ], $settings->userGroup);
                    }

                    $token = $tokenService->create($user, $schemaId);

                    return [
                        'accessToken' => $token,
                        'user' => $user,
                        'schema' => $gql->getSchemaById($schemaId)->name,
                    ];
                },
            ];
        }

        if ($settings->permissionType === 'multiple' && $this->_validateTwitterSettings()) {
            foreach ($userGroups as $userGroup) {
                $handle = ucfirst($userGroup->handle);

                $event->mutations["facebookSignIn{$handle}"] = [
                    'description' => "Authenticates a {$userGroup->name} using a Facebook Sign-In token. Returns user and token.",
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'code' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($users, $gql, $settings, $userService, $tokenService, $userGroup) {
                        $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                        if (!$schemaId) {
                            throw new Error($settings->invalidSchema);
                        }

                        $code = $arguments['code'];
                        $tokenUser = $this->_getUserFromFacebookToken($code);
                        $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

                        if (!$user) {
                            if (!($settings->granularSchemas["group-{$userGroup->id}"]['allowRegistration'] ?? false)) {
                                throw new Error($settings->invalidSchema);
                            }

                            $user = $userService->create([
                                'email' => $tokenUser['email'],
                                'password' => '',
                                'firstName' => $tokenUser['firstName'],
                                'lastName' => $tokenUser['lastName'],
                            ], $userGroup->id);
                        }

                        $token = $tokenService->create($user, $schemaId);

                        return [
                            'accessToken' => $token,
                            'user' => $user,
                            'schema' => $gql->getSchemaById($schemaId)->name,
                        ];
                    },
                ];
            }
        }

        if ($settings->permissionType === 'single' && $this->_validateTwitterSettings()) {
            $event->mutations['twitterSignIn'] = [
                'description' => 'Authenticates a user using a Twitter Sign-In token. Returns user and token.',
                'type' => Type::nonNull(Auth::getType()),
                'args' => [
                    'oauthToken' => Type::nonNull(Type::string()),
                    'oauthVerifier' => Type::nonNull(Type::string()),
                ],
                'resolve' => function ($source, array $arguments) use ($users, $gql, $settings, $userService, $tokenService) {
                    $schemaId = $settings->schemaId;

                    if (!$schemaId) {
                        throw new Error($settings->invalidSchema);
                    }

                    $oauthToken = $arguments['oauthToken'];
                    $oauthVerifier = $arguments['oauthVerifier'];
                    $tokenUser = $this->_getUserFromTwitterToken($oauthToken, $oauthVerifier);
                    $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

                    if (!$user) {
                        if (!$settings->allowRegistration) {
                            throw new Error($settings->userNotFound);
                        }

                        $user = $userService->create([
                            'email' => $tokenUser['email'],
                            'password' => '',
                            'firstName' => $tokenUser['firstName'],
                            'lastName' => $tokenUser['lastName'],
                        ], $settings->userGroup);
                    }

                    $token = $tokenService->create($user, $schemaId);

                    return [
                        'accessToken' => $token,
                        'user' => $user,
                        'schema' => $gql->getSchemaById($schemaId)->name,
                    ];
                },
            ];
        }

        if ($settings->permissionType === 'multiple' && $this->_validateTwitterSettings()) {
            foreach ($userGroups as $userGroup) {
                $handle = ucfirst($userGroup->handle);

                $event->mutations["twitterSignIn{$handle}"] = [
                    'description' => "Authenticates a {$userGroup->name} using a Twitter Sign-In token. Returns user and token.",
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'oauthToken' => Type::nonNull(Type::string()),
                        'oauthVerifier' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($users, $gql, $settings, $userService, $tokenService, $userGroup) {
                        $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                        if (!$schemaId) {
                            throw new Error($settings->invalidSchema);
                        }

                        $oauthToken = $arguments['oauthToken'];
                        $oauthVerifier = $arguments['oauthVerifier'];
                        $tokenUser = $this->_getUserFromTwitterToken($oauthToken, $oauthVerifier);
                        $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

                        if (!$user) {
                            if (!($settings->granularSchemas["group-{$userGroup->id}"]['allowRegistration'] ?? false)) {
                                throw new Error($settings->invalidSchema);
                            }

                            $user = $userService->create([
                                'email' => $tokenUser['email'],
                                'password' => '',
                                'firstName' => $tokenUser['firstName'],
                                'lastName' => $tokenUser['lastName'],
                            ], $userGroup->id);
                        }

                        $token = $tokenService->create($user, $schemaId);

                        return [
                            'accessToken' => $token,
                            'user' => $user,
                            'schema' => $gql->getSchemaById($schemaId)->name,
                        ];
                    },
                ];
            }
        }
    }

    // Protected Methods
    // =========================================================================

    protected function _validateFacebookSettings(): bool
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        return $settings->facebookAppId && $settings->facebookAppSecret && $settings->facebookRedirectUrl;
    }

    protected function _validateTwitterSettings(): bool
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        return $settings->twitterApiKey && $settings->twitterApiKeySecret && $settings->twitterRedirectUrl;
    }

    protected function _getUserFromGoogleToken(string $idToken): array
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $client = new Google_Client(['client_id' => $settings->googleClientId]);
        $payload = $client->verifyIdToken($idToken);

        if (!$payload) {
            throw new Error($settings->googleTokenIdInvalid);
        }

        $email = $payload['email'];

        if (!$email || !isset($email)) {
            throw new Error($settings->emailNotInScope);
        }

        if ($settings->allowedGoogleDomains) {
            $domains = explode(',', str_replace(['http://', 'https://', 'www.', ' ', '/'], '', $settings->allowedGoogleDomains));
            $hd = $payload['hd'];

            if (!in_array($hd, $domains)) {
                throw new Error($settings->googleEmailMismatch);
            }
        }

        $firstName = $payload['given_name'];
        $lastName = $payload['family_name'];

        return compact(
            'email',
            'firstName',
            'lastName',
        );
    }

    protected function _getUserFromFacebookToken(string $code): array
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();

        $client = new Facebook([
            'app_id' => $settings->facebookAppId,
            'app_secret' => $settings->facebookAppSecret,
        ]);

        $accessToken = $client->getOAuth2Client()->getAccessTokenFromCode($code, $settings->facebookRedirectUrl);

        if (!$accessToken) {
            throw new Error($settings->invalidOauthToken);
        }

        $user = $client->get('/me?fields=id,name,email', $accessToken->getValue())->getGraphUser();
        $email = $user['email'];

        if (!$email || !isset($email)) {
            throw new Error($settings->emailNotInScope);
        }

        $name = explode(' ', $user['name'] ?? '', 1);
        $firstName = $name[0] ?? '';
        $lastName = $name[1] ?? '';

        return compact(
            'email',
            'firstName',
            'lastName',
        );
    }

    protected function _getUserFromTwitterToken(string $oauthToken, string $oauthVerifier): array
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $session = Craft::$app->getSession();
        $sessionOauthToken = $session->get('oauthToken');
        $sessionOauthTokenSecret = $session->get('oauthTokenSecret');

        if ($oauthToken !== $sessionOauthToken) {
            throw new Error($settings->invalidOauthToken);
        }

        $client = new TwitterOAuth($settings->twitterApiKey, $settings->twitterApiKeySecret, $sessionOauthToken, $sessionOauthTokenSecret);
        $accessToken = $client->oauth('oauth/access_token', ['oauth_verifier' => $oauthVerifier]);

        $client = new TwitterOAuth($settings->twitterApiKey, $settings->twitterApiKeySecret, $accessToken['oauth_token'], $accessToken['oauth_token_secret']);
        $user = $client->get('account/verify_credentials', ['include_email' => true, 'entities' => false, 'skip_status' => true]);

        $email = $user->email;

        if (!$email || !isset($email)) {
            throw new Error($settings->emailNotInScope);
        }

        $name = explode(' ', $user->name ?? '', 1);
        $firstName = $name[0] ?? '';
        $lastName = $name[1] ?? '';

        $session->remove('oauthToken');
        $session->remove('oauthTokenSecret');

        return compact(
            'email',
            'firstName',
            'lastName',
        );
    }
}

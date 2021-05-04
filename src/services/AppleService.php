<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\services\Gql;
use craft\services\UserGroups;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use GuzzleHttp\Client;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\gql\Platform;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use Throwable;
use yii\base\Event;

class AppleService extends Component
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
     * Registers Sign in with Apple queries
     *
     * @param RegisterGqlQueriesEvent $event
     */
    public function registerGqlQueries(RegisterGqlQueriesEvent $event)
    {
        if (!$this->_validateWebSettings()) {
            return;
        }

        $event->queries['appleOauthUrl'] = [
            'description' => 'Generates the Apple OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function () {
                $settings = GraphqlAuthentication::$settings;

                $url = 'https://appleid.apple.com/auth/authorize?' . http_build_query([
                    'response_type' => 'code',
                    'response_mode' => 'form_post',
                    'client_id' => GraphqlAuthentication::getInstance()->getSettingsData($settings->appleServiceId),
                    'redirect_uri' => GraphqlAuthentication::getInstance()->getSettingsData($settings->appleRedirectUrl),
                    'scope' => 'name email',
                ]);

                return $url;
            },
        ];
    }

    /**
     * Registers Sign in with Apple mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        if (!$this->_validateNativeSettings() && !$this->_validateWebSettings()) {
            return;
        }

        $args = [
            'code' => Type::nonNull(Type::string()),
        ];

        if ($this->_validateNativeSettings() && $this->_validateWebSettings()) {
            $args['platform'] = Platform::getType();
        }

        $defaultPlatform = 'native';

        if (!$this->_validateNativeSettings() && $this->_validateWebSettings()) {
            $defaultPlatform = 'web';
        }

        switch (GraphqlAuthentication::$settings->permissionType) {
            case 'single':
                $event->mutations['appleSignIn'] = [
                    'description' => 'Authenticates a user using an Apple Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => $args,
                    'resolve' => function ($source, array $arguments) use ($defaultPlatform) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $code = $arguments['code'];
                        $platform = $arguments['platform'] ?? $defaultPlatform;
                        $tokenUser = $this->_getUserFromToken($code, $platform);

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

                    $event->mutations["appleSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using an Apple Sign-In token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => $args,
                        'resolve' => function ($source, array $arguments) use ($userGroup, $defaultPlatform) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema, 'INVALID');
                            }

                            $code = $arguments['code'];
                            $platform = $arguments['platform'] ?? $defaultPlatform;
                            $tokenUser = $this->_getUserFromToken($code, $platform);

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
     * Ensures native settings are set
     *
     * @return bool
     */
    protected function _validateNativeSettings(): bool
    {
        $settings = GraphqlAuthentication::$settings;
        return (bool) $settings->appleClientId && (bool) $settings->appleClientSecret;
    }

    /**
     * Ensures web settings are set
     *
     * @return bool
     */
    protected function _validateWebSettings(): bool
    {
        $settings = GraphqlAuthentication::$settings;
        return (bool) $settings->appleServiceId && (bool) $settings->appleServiceSecret && (bool) $settings->appleRedirectUrl;
    }

    /**
     * Gets user details from Sign in with Apple token
     *
     * @param string $code
     * @param string $platform
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $code, string $platform): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;
        $client = new Client();

        $id = $settings->appleClientId;
        $secret = $settings->appleClientSecret;
        $redirect = null;

        if ($platform === 'web') {
            $id = $settings->appleServiceId;
            $secret = $settings->appleServiceSecret;
            $redirect = $settings->appleRedirectUrl;
        }

        $params = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'client_id' => GraphqlAuthentication::getInstance()->getSettingsData($id),
            'client_secret' => GraphqlAuthentication::getInstance()->getSettingsData($secret),
        ];

        if ($redirect) {
            $params['redirect_uri'] = GraphqlAuthentication::getInstance()->getSettingsData($redirect);
        }

        try {
            $response = json_decode($client->request('POST', 'https://appleid.apple.com/auth/token', [
                'form_params' => $params,
            ])->getBody()->getContents());
        } catch (Throwable $e) {
            $errorService->throw($settings->invalidOauthToken, 'INVALID');
        }

        $claims = explode('.', $response->id_token)[1];
        $claims = json_decode(base64_decode($claims));

        $email = $claims->email;

        if (!$email || !isset($email)) {
            $errorService->throw($settings->emailNotInScope, 'INVALID');
        }

        $name = explode(' ', $claims->name ?? '', 1);
        $firstName = $name[0] ?? '';
        $lastName = $name[1] ?? '';

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

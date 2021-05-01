<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\services\Gql;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use GuzzleHttp\Client;
use jamesedmonston\graphqlauthentication\gql\Auth;
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
        if (!$this->_validateSettings()) {
            return;
        }

        $event->queries['appleOauthUrl'] = [
            'description' => 'Generates the Apple OAuth URL for allowing users to authenticate.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function () {
                $settings = GraphqlAuthentication::$plugin->getSettings();
                $session = Craft::$app->getSession();

                $state = bin2hex(random_bytes(5));
                $session->set('state', $state);

                $url = 'https://appleid.apple.com/auth/authorize?' . http_build_query([
                    'response_type' => 'code',
                    'response_mode' => 'form_post',
                    'client_id' => GraphqlAuthentication::$plugin->getSettingsData($settings->appleClientId),
                    'redirect_uri' => GraphqlAuthentication::$plugin->getSettingsData($settings->appleRedirectUrl),
                    'state' => $state,
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
        if (!$this->_validateSettings()) {
            return;
        }

        $userGroups = Craft::$app->getUserGroups()->getAllGroups();
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $socialService = GraphqlAuthentication::$plugin->getInstance()->social;
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;

        switch ($settings->permissionType) {
            case 'single':
                $event->mutations['appleSignIn'] = [
                    'description' => 'Authenticates a user using an Apple Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'code' => Type::nonNull(Type::string()),
                        'state' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService) {
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            $errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $code = $arguments['code'];
                        $state = $arguments['state'];
                        $tokenUser = $this->_getUserFromToken($code, $state);

                        $user = $socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["appleSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using an Apple Sign-In token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'code' => Type::nonNull(Type::string()),
                            'state' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService, $userGroup) {
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                $errorService->throw($settings->invalidSchema, 'INVALID');
                            }

                            $code = $arguments['code'];
                            $state = $arguments['state'];
                            $tokenUser = $this->_getUserFromToken($code, $state);

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
        return (bool) $settings->appleClientId && (bool) $settings->appleClientSecret && (bool) $settings->appleRedirectUrl;
    }

    /**
     * Gets user details from Sign in with Apple token
     *
     * @param string $code
     * @param string $state
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $code, string $state): array
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;
        $session = Craft::$app->getSession();
        $sessionState = $session->get('state');

        if ($state !== $sessionState) {
            $errorService->throw($settings->invalidOauthToken, 'INVALID');
        }

        $client = new Client();

        try {
            $response = json_decode($client->request('POST', 'https://appleid.apple.com/auth/token', [
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'client_id' => GraphqlAuthentication::$plugin->getSettingsData($settings->appleClientId),
                    'client_secret' => GraphqlAuthentication::$plugin->getSettingsData($settings->appleClientSecret),
                    'redirect_uri' => GraphqlAuthentication::$plugin->getSettingsData($settings->appleRedirectUrl),
                ],
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

        $session->remove('state');

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

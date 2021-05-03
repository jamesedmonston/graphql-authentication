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
                $settings = GraphqlAuthentication::$settings;

                $url = 'https://appleid.apple.com/auth/authorize?' . http_build_query([
                    'response_type' => 'code',
                    'response_mode' => 'form_post',
                    'client_id' => GraphqlAuthentication::getInstance()->getSettingsData($settings->appleClientId),
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
        if (!$this->_validateSettings()) {
            return;
        }

        switch (GraphqlAuthentication::$settings->permissionType) {
            case 'single':
                $event->mutations['appleSignIn'] = [
                    'description' => 'Authenticates a user using an Apple Sign-In token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'code' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $code = $arguments['code'];
                        $tokenUser = $this->_getUserFromToken($code);

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
                        'args' => [
                            'code' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function ($source, array $arguments) use ($userGroup) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema, 'INVALID');
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
        return (bool) $settings->appleClientId && (bool) $settings->appleClientSecret && (bool) $settings->appleRedirectUrl;
    }

    /**
     * Gets user details from Sign in with Apple token
     *
     * @param string $code
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $code): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;
        $client = new Client();

        try {
            $response = json_decode($client->request('POST', 'https://appleid.apple.com/auth/token', [
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'code' => $code,
                    'client_id' => GraphqlAuthentication::getInstance()->getSettingsData($settings->appleClientId),
                    'client_secret' => GraphqlAuthentication::getInstance()->getSettingsData($settings->appleClientSecret),
                    'redirect_uri' => GraphqlAuthentication::getInstance()->getSettingsData($settings->appleRedirectUrl),
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

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

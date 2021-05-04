<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\services\Gql;
use craft\services\UserGroups;
use Google_Client;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class GoogleService extends Component
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
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    /**
     * Registers Google Sign-In mutations
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
                $event->mutations['googleSignIn'] = [
                    'description' => 'Authenticates a user using a Google Sign-In ID token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'idToken' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $idToken = $arguments['idToken'];
                        $tokenUser = $this->_getUserFromToken($idToken);

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

                    $event->mutations["googleSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Google Sign-In ID token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'idToken' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function ($source, array $arguments) use ($userGroup) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema, 'INVALID');
                            }

                            $idToken = $arguments['idToken'];
                            $tokenUser = $this->_getUserFromToken($idToken);

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
        return (bool) $settings->googleClientId;
    }

    /**
     * Gets user details from Google Sign-In token
     *
     * @param string $idToken
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $idToken): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        $client = new Google_Client([
            'client_id' => GraphqlAuthentication::getInstance()->getSettingsData($settings->googleClientId),
        ]);

        $payload = $client->verifyIdToken($idToken);

        if (!$payload) {
            $errorService->throw($settings->googleTokenIdInvalid, 'INVALID');
        }

        $email = $payload['email'];

        if (!$email || !isset($email)) {
            $errorService->throw($settings->emailNotInScope, 'INVALID');
        }

        if ($settings->allowedGoogleDomains) {
            GraphqlAuthentication::$socialService->verifyEmailDomain(
                $email,
                $settings->allowedGoogleDomains,
                $settings->googleEmailMismatch
            );
        }

        $name = $payload['name'] ?? '';
        $firstName = $payload['given_name'] ?? null;
        $lastName = $payload['family_name'] ?? null;

        $name = explode(' ', $name, 1);
        $firstName = $firstName ?? $name[0] ?? '';
        $lastName = $lastName ?? $name[1] ?? '';

        return compact(
            'email',
            'firstName',
            'lastName'
        );
    }
}

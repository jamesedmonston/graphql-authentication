<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\services\Gql;
use Google_Client;
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
                $event->mutations['googleSignIn'] = [
                    'description' => 'Authenticates a user using a Google Sign-In ID token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'idToken' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService) {
                        $schemaId = $settings->schemaId;

                        if (!$schemaId) {
                            $errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $idToken = $arguments['idToken'];
                        $tokenUser = $this->_getUserFromToken($idToken);

                        $user = $socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["googleSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Google Sign-In ID token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'idToken' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function ($source, array $arguments) use ($settings, $socialService, $errorService, $userGroup) {
                            $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                            if (!$schemaId) {
                                $errorService->throw($settings->invalidSchema, 'INVALID');
                            }

                            $idToken = $arguments['idToken'];
                            $tokenUser = $this->_getUserFromToken($idToken);

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
        return (bool) $settings->googleClientId;
    }

    protected function _getUserFromToken(string $idToken): array
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;
        $client = new Google_Client([
            'client_id' => GraphqlAuthentication::$plugin->getSettingsData($settings->googleClientId)
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
            GraphqlAuthentication::$plugin->getInstance()->social->verifyEmailDomain(
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

<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\services\Gql;
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
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    public function registerGqlMutations(Event $event)
    {
        $users = Craft::$app->getUsers();
        $gql = Craft::$app->getGql();
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
                    $tokenUser = $this->_getUserFromToken($idToken);
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
            $userGroups = Craft::$app->getUserGroups()->getAllGroups();

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
                        $tokenUser = $this->_getUserFromToken($idToken);
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

    protected function _getUserFromToken(string $idToken)
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();

        if (!$settings->googleClientId) {
            throw new Error($settings->googleClientNotFound);
        }

        $client = new Google_Client(['client_id' => $settings->googleClientId]);
        $payload = $client->verifyIdToken($idToken);

        if (!$payload) {
            throw new Error($settings->googleTokenIdInvalid);
        }

        $email = $payload['email'];

        if (!$email || !isset($email)) {
            throw new Error($settings->googleEmailNotInScope);
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
}

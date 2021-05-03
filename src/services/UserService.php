<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\gql\arguments\elements\User as UserArguments;
use craft\gql\interfaces\elements\User as ElementsUser;
use craft\helpers\DateTimeHelper;
use craft\helpers\StringHelper;
use craft\records\User as UserRecord;
use craft\services\Elements;
use craft\services\Fields;
use craft\services\Gql;
use craft\services\ProjectConfig;
use craft\services\UserGroups;
use craft\services\UserPermissions;
use craft\services\Users;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class UserService extends Component
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
     * Registers user queries
     *
     * @param RegisterGqlQueriesEvent $event
     */
    public function registerGqlQueries(RegisterGqlQueriesEvent $event)
    {
        $event->queries['viewer'] = [
            'description' => 'Gets authenticated user.',
            'type' => ElementsUser::getType(),
            'args' => [],
            'resolve' => function () {
                $user = GraphqlAuthentication::$tokenService->getUserFromToken();

                if (!$user) {
                    GraphqlAuthentication::$errorService->throw(GraphqlAuthentication::$settings->userNotFound, 'INVALID');
                }

                return $user;
            },
        ];
    }

    /**
     * Registers user mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        $settings = GraphqlAuthentication::$settings;
        $tokenService = GraphqlAuthentication::$tokenService;
        $errorService = GraphqlAuthentication::$errorService;

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        /** @var Users */
        $usersService = Craft::$app->getUsers();

        /** @var UserPermissions */
        $permissionsService = Craft::$app->getUserPermissions();

        /** @var Gql */
        $gqlService = Craft::$app->getGql();

        /** @var Fields */
        $fieldsService = Craft::$app->getFields();

        $event->mutations['authenticate'] = [
            'description' => 'Logs a user in. Returns user and token.',
            'type' => Type::nonNull(Auth::getType()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
                'password' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService, $usersService, $permissionsService) {
                $email = $arguments['email'];
                $password = $arguments['password'];

                $user = $usersService->getUserByUsernameOrEmail($email);

                if (!$user) {
                    $errorService->throw($settings->invalidLogin, 'INVALID');
                }

                if ($user->status !== 'active') {
                    $errorService->throw($settings->userNotActivated, 'INVALID');
                }

                $userPermissions = $permissionsService->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissionsService->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                if (!$user->authenticate($password)) {
                    $permissionsService->saveUserPermissions($user->id, $userPermissions);
                    $errorService->throw($settings->invalidLogin, 'INVALID');
                }

                $permissionsService->saveUserPermissions($user->id, $userPermissions);

                $schemaId = $settings->schemaId ?? null;

                if ($settings->permissionType === 'multiple') {
                    $userGroup = $user->getGroups()[0] ?? null;

                    if ($userGroup) {
                        $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;
                    }
                }

                if (!$schemaId) {
                    $errorService->throw($settings->invalidSchema, 'INVALID');
                }

                $this->_updateLastLogin($user);
                $token = $tokenService->create($user, $schemaId);
                return $this->getResponseFields($user, $schemaId, $token);
            },
        ];

        if ($settings->permissionType === 'single' && $settings->allowRegistration) {
            $event->mutations['register'] = [
                'description' => 'Registers a user. Returns user and token.',
                'type' => Type::nonNull(Auth::getType()),
                'args' => array_merge(
                    [
                        'email' => Type::nonNull(Type::string()),
                        'password' => Type::nonNull(Type::string()),
                        'username' => Type::string(),
                        'firstName' => Type::string(),
                        'lastName' => Type::string(),
                        'preferredLanguage' => Type::string(),
                    ],
                    UserArguments::getContentArguments()
                ),
                'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService) {
                    $schemaId = $settings->schemaId;

                    if (!$schemaId) {
                        $errorService->throw($settings->invalidSchema, 'INVALID');
                    }

                    $user = $this->create($arguments, $settings->userGroup);
                    $token = $tokenService->create($user, $schemaId);

                    return $this->getResponseFields($user, $schemaId, $token);
                },
            ];
        }

        if ($settings->permissionType === 'multiple') {
            /** @var UserGroups */
            $userGroupsService = Craft::$app->getUserGroups();
            $userGroups = $userGroupsService->getAllGroups();

            foreach ($userGroups as $userGroup) {
                if (!($settings->granularSchemas["group-{$userGroup->id}"]['allowRegistration'] ?? false)) {
                    continue;
                }

                $handle = ucfirst($userGroup->handle);

                $event->mutations["register{$handle}"] = [
                    'description' => "Registers a {$userGroup->name} user. Returns user and token.",
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => array_merge(
                        [
                            'email' => Type::nonNull(Type::string()),
                            'password' => Type::nonNull(Type::string()),
                            'firstName' => Type::string(),
                            'lastName' => Type::string(),
                        ],
                        UserArguments::getContentArguments()
                    ),
                    'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService, $userGroup) {
                        $schemaId = $settings->granularSchemas["group-{$userGroup->id}"]['schemaId'] ?? null;

                        if (!$schemaId) {
                            $errorService->throw($settings->invalidSchema, 'INVALID');
                        }

                        $user = $this->create($arguments, $userGroup->id);
                        $token = $tokenService->create($user, $schemaId);

                        return $this->getResponseFields($user, $schemaId, $token);
                    },
                ];
            }
        }

        $event->mutations['activateUser'] = [
            'description' => 'Activates user. Requires `code` and `id` from Craft activation email. Returns success message.',
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'code' => Type::nonNull(Type::string()),
                'id' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $errorService, $usersService) {
                $code = $arguments['code'];
                $id = $arguments['id'];

                $user = $usersService->getUserByUid($id);

                if (!$user || !$usersService->isVerificationCodeValidForUser($user, $code)) {
                    $errorService->throw($settings->invalidRequest, 'INVALID');
                }

                $usersService->activateUser($user);
                return $settings->userActivated;
            },
        ];

        $event->mutations['resendActivation'] = [
            'description' => "Resends an activation email to the user. Returns success message.",
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $usersService) {
                $email = $arguments['email'];
                $user = $usersService->getUserByUsernameOrEmail($email);
                $message = $settings->activationEmailSent;

                if (!$user) {
                    return $message;
                }

                $usersService->sendActivationEmail($user);
                return $message;
            },
        ];

        $event->mutations['forgottenPassword'] = [
            'description' => "Sends a password reset email to the user's email address. Returns success message.",
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $usersService) {
                $email = $arguments['email'];
                $user = $usersService->getUserByUsernameOrEmail($email);
                $message = $settings->passwordResetSent;

                if (!$user) {
                    return $message;
                }

                $usersService->sendPasswordResetEmail($user);
                return $message;
            },
        ];

        $event->mutations['setPassword'] = [
            'description' => 'Sets password for unauthenticated user. Requires `code` and `id` from Craft reset password email. Returns success message.',
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'password' => Type::nonNull(Type::string()),
                'code' => Type::nonNull(Type::string()),
                'id' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $errorService, $elementsService, $usersService) {
                $password = $arguments['password'];
                $code = $arguments['code'];
                $id = $arguments['id'];

                $user = $usersService->getUserByUid($id);

                if (!$user || !$usersService->isVerificationCodeValidForUser($user, $code)) {
                    $errorService->throw($settings->invalidRequest, 'INVALID');
                }

                $user->newPassword = $password;

                if (!$elementsService->saveElement($user)) {
                    $errorService->throw(json_encode($user->getErrors()), 'INVALID');
                }

                $usersService->activateUser($user);
                return $settings->passwordSaved;
            },
        ];

        $event->mutations['updatePassword'] = [
            'description' => 'Updates password for authenticated user. Requires access token and current password. Returns success message.',
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'currentPassword' => Type::nonNull(Type::string()),
                'newPassword' => Type::nonNull(Type::string()),
                'confirmPassword' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService, $elementsService, $usersService, $permissionsService) {
                $user = $tokenService->getUserFromToken();

                if (!$user) {
                    $errorService->throw($settings->invalidPasswordUpdate, 'INVALID');
                }

                $newPassword = $arguments['newPassword'];
                $confirmPassword = $arguments['confirmPassword'];

                if ($newPassword !== $confirmPassword) {
                    $errorService->throw($settings->invalidPasswordMatch, 'INVALID');
                }

                $currentPassword = $arguments['currentPassword'];
                $userPermissions = $permissionsService->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissionsService->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                $user = $usersService->getUserByUsernameOrEmail($user->email);

                if (!$user->authenticate($currentPassword)) {
                    $permissionsService->saveUserPermissions($user->id, $userPermissions);
                    $errorService->throw($settings->invalidPasswordUpdate, 'INVALID');
                }

                $permissionsService->saveUserPermissions($user->id, $userPermissions);

                $user->newPassword = $newPassword;

                if (!$elementsService->saveElement($user)) {
                    $errorService->throw(json_encode($user->getErrors()), 'INVALID');
                }

                return $settings->passwordUpdated;
            },
        ];

        $event->mutations['updateViewer'] = [
            'description' => 'Updates authenticated user. Returns user.',
            'type' => ElementsUser::getType(),
            'args' => array_merge(
                [
                    'email' => Type::string(),
                    'username' => Type::string(),
                    'firstName' => Type::string(),
                    'lastName' => Type::string(),
                    'preferredLanguage' => Type::string(),
                ],
                UserArguments::getContentArguments()
            ),
            'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService, $elementsService, $usersService, $fieldsService) {
                $user = $tokenService->getUserFromToken();

                if (!$user) {
                    $errorService->throw($settings->invalidUserUpdate, 'INVALID');
                }

                $email = $arguments['email'];
                $firstName = $arguments['firstName'];
                $lastName = $arguments['lastName'];
                $preferredLanguage = $arguments['preferredLanguage'];

                if (isset($email)) {
                    if ($user->username === $user->email) {
                        $user->username = $email;
                    }

                    $user->email = $email;
                }

                if (isset($username)) {
                    $user->username = $username;
                }

                if (isset($firstName)) {
                    $user->firstName = $firstName;
                }

                if (isset($lastName)) {
                    $user->lastName = $lastName;
                }

                if (isset($preferredLanguage)) {
                    $usersService->saveUserPreferences($user, ['language' => $preferredLanguage]);
                }

                $customFields = UserArguments::getContentArguments();

                foreach ($customFields as &$key) {
                    if (is_array($key) && isset($key['name'])) {
                        $key = $key['name'];
                    }

                    if (!isset($arguments[$key]) || !count($arguments[$key])) {
                        continue;
                    }

                    $field = $fieldsService->getFieldByHandle($key);
                    $type = get_class($field);
                    $value = $arguments[$key];

                    if (!StringHelper::containsAny($type, ['Entries', 'Categories', 'Assets'])) {
                        $value = $value[0];
                    }

                    $user->setFieldValue($key, $value);
                }

                if (!$elementsService->saveElement($user)) {
                    $errorService->throw(json_encode($user->getErrors()), 'INVALID');
                }

                return $user;
            },
        ];

        $event->mutations['deleteCurrentToken'] = [
            'description' => 'Deletes authenticated user access token. Useful for logging out of current device. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () use ($settings, $tokenService, $errorService, $gqlService) {
                $token = $tokenService->getHeaderToken();

                if (!$token) {
                    $errorService->throw($settings->tokenNotFound, 'INVALID');
                }

                $gqlService->deleteTokenById($token->id);
                return true;
            },
        ];

        $event->mutations['deleteAllTokens'] = [
            'description' => 'Deletes all access tokens belonging to the authenticated user. Useful for logging out of all devices. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () use ($settings, $tokenService, $errorService, $gqlService) {
                $user = $tokenService->getUserFromToken();

                if (!$user) {
                    $errorService->throw($settings->tokenNotFound, 'INVALID');
                }

                $savedTokens = $gqlService->getTokens();

                if (!$savedTokens || !count($savedTokens)) {
                    $errorService->throw($settings->tokenNotFound, 'INVALID');
                }

                foreach ($savedTokens as $savedToken) {
                    if (StringHelper::contains($savedToken->name, "user-{$user->id}")) {
                        $gqlService->deleteTokenById($savedToken->id);
                    }
                }

                return true;
            },
        ];
    }

    /**
     * Creates a user
     *
     * @param array $arguments
     * @param int $userGroup
     * @return User
     * @throws Error
     */
    public function create(array $arguments, int $userGroup): User
    {
        $email = $arguments['email'];
        $password = $arguments['password'];
        $username = $arguments['username'] ?? null;
        $firstName = $arguments['firstName'] ?? null;
        $lastName = $arguments['lastName'] ?? null;

        $user = new User();
        $user->username = $email;
        $user->email = $email;

        if ($username) {
            $user->username = $username;
        }

        if ($firstName) {
            $user->firstName = $firstName;
        }

        if ($lastName) {
            $user->lastName = $lastName;
        }

        if ($password) {
            $user->newPassword = $password;
        }

        $customFields = UserArguments::getContentArguments();

        /** @var Fields */
        $fieldsService = Craft::$app->getFields();

        foreach ($customFields as $key) {
            if (is_array($key) && isset($key['name'])) {
                $key = $key['name'];
            }

            if (!isset($arguments[$key]) || !count($arguments[$key])) {
                continue;
            }

            $field = $fieldsService->getFieldByHandle($key);
            $type = get_class($field);
            $value = $arguments[$key];

            if (!StringHelper::containsAny($type, ['Entries', 'Categories', 'Assets'])) {
                $value = $value[0];
            }

            $user->setFieldValue($key, $value);
        }

        /** @var ProjectConfig */
        $projectConfigService = Craft::$app->getProjectConfig();
        $requiresVerification = $projectConfigService->get('users.requireEmailVerification');

        if ($requiresVerification) {
            $user->pending = true;
        }

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        if (!$elementsService->saveElement($user)) {
            GraphqlAuthentication::$errorService->throw(json_encode($user->getErrors()), 'INVALID');
        }

        /** @var Users */
        $usersService = Craft::$app->getUsers();

        if ($userGroup) {
            $usersService->assignUserToGroups($user->id, [$userGroup]);
        }

        if ($requiresVerification) {
            $usersService->sendActivationEmail($user);
        }

        $preferredLanguage = $arguments['preferredLanguage'] ?? null;

        if ($preferredLanguage) {
            $usersService->saveUserPreferences($user, ['language' => $preferredLanguage]);
        }

        $this->_updateLastLogin($user);
        return $user;
    }

    /**
     * Formats authentication/registration mutation responses
     *
     * @param User $user
     * @param int $schemaId
     * @param array $schemaId
     * @return array
     */
    public function getResponseFields(User $user, int $schemaId, array $token): array
    {
        /** @var Gql */
        $gqlService = Craft::$app->getGql();

        return [
            'user' => $user,
            'schema' => $gqlService->getSchemaById($schemaId)->name,
            'jwt' => $token['jwt'],
            'jwtExpiresAt' => $token['jwtExpiresAt'],
            'refreshToken' => $token['refreshToken'],
            'refreshTokenExpiresAt' => $token['refreshTokenExpiresAt'],
        ];
    }

    // Protected Methods
    // =========================================================================

    /**
     * Updates user's last login time
     *
     * @param User $user
     */
    protected function _updateLastLogin(User $user)
    {
        $now = DateTimeHelper::currentUTCDateTime();
        $userRecord = UserRecord::findOne($user->id);
        $userRecord->lastLoginDate = $now;
        $userRecord->save();
    }
}

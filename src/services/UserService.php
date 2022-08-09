<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\fields\Table;
use craft\gql\arguments\elements\User as UserArguments;
use craft\gql\interfaces\elements\User as ElementsUser;
use craft\gql\resolvers\mutations\Asset;
use craft\gql\types\input\File;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Elements;
use craft\services\Fields;
use craft\services\Gql;
use craft\services\ProjectConfig;
use craft\services\UserGroups;
use craft\services\UserPermissions;
use craft\services\Users;
use craft\services\Volumes;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\ResolveInfo;
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
            'resolve' => function() {
                return GraphqlAuthentication::$tokenService->getUserFromToken();
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

        /** @var Volumes */
        $volumesService = Craft::$app->getVolumes();

        /** @var ProjectConfig */
        $projectConfigService = Craft::$app->getProjectConfig();

        /** @var Fields */
        $fieldsService = Craft::$app->getFields();

        $userFields = $fieldsService->getLayoutByType(User::class)->getCustomFields();
        $userArguments = [];

        foreach ($userFields as $userField) {
            $type = $userField->getContentGqlMutationArgumentType();
            $fieldType = $type;

            if ($userField instanceof Table) {
                $fieldType = Type::listOf($type);
            }

            $userArguments[$userField->handle] = $fieldType;
        }

        $event->mutations['authenticate'] = [
            'description' => 'Logs a user in. Returns user and token.',
            'type' => Type::nonNull(Auth::getType()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
                'password' => Type::nonNull(Type::string()),
            ],
            'resolve' => function($source, array $arguments) use ($settings, $tokenService, $errorService, $usersService, $permissionsService) {
                $email = $arguments['email'];
                $password = $arguments['password'];

                if (!$user = $usersService->getUserByUsernameOrEmail($email)) {
                    $errorService->throw($settings->invalidLogin);
                }

                if ($user->status !== 'active') {
                    $errorService->throw($settings->userNotActivated);
                }

                $userPermissions = $permissionsService->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissionsService->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                if (!$user->authenticate($password)) {
                    if ($user->authError === User::AUTH_PASSWORD_RESET_REQUIRED) {
                        Craft::$app->getUsers()->sendPasswordResetEmail($user);
                        $errorService->throw($settings->passwordResetRequired, true);
                    }

                    $permissionsService->saveUserPermissions($user->id, $userPermissions);
                    $errorService->throw($settings->invalidLogin);
                }

                $permissionsService->saveUserPermissions($user->id, $userPermissions);

                $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                if ($settings->permissionType === 'multiple') {
                    $userGroup = $user->getGroups()[0] ?? null;

                    if ($userGroup) {
                        $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                        $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();
                    }
                }

                if (!$schemaId) {
                    $errorService->throw($settings->invalidSchema);
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
                    $userArguments
                ),
                'resolve' => function($source, array $arguments) use ($settings, $tokenService, $errorService) {
                    $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                    if (!$schemaId) {
                        $errorService->throw($settings->invalidSchema);
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
                            'username' => Type::string(),
                            'firstName' => Type::string(),
                            'lastName' => Type::string(),
                            'preferredLanguage' => Type::string(),
                        ],
                        $userArguments
                    ),
                    'resolve' => function($source, array $arguments) use ($settings, $tokenService, $errorService, $userGroup) {
                        $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                        $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();

                        if (!$schemaId) {
                            $errorService->throw($settings->invalidSchema);
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
            'resolve' => function($source, array $arguments) use ($settings, $errorService, $usersService) {
                $code = $arguments['code'];
                $id = $arguments['id'];

                $user = $usersService->getUserByUid($id);

                if (!$user || !$usersService->isVerificationCodeValidForUser($user, $code)) {
                    $errorService->throw($settings->invalidRequest);
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
            'resolve' => function($source, array $arguments) use ($settings, $usersService) {
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
            'resolve' => function($source, array $arguments) use ($settings, $usersService) {
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
            'resolve' => function($source, array $arguments) use ($settings, $errorService, $elementsService, $usersService) {
                $password = $arguments['password'];
                $code = $arguments['code'];
                $id = $arguments['id'];

                $user = $usersService->getUserByUid($id);

                if (!$user || !$usersService->isVerificationCodeValidForUser($user, $code)) {
                    $errorService->throw($settings->invalidRequest);
                }

                $user->newPassword = $password;
                $user->setScenario(User::SCENARIO_PASSWORD);

                if (!$elementsService->saveElement($user)) {
                    $errors = $user->getErrors();
                    $errorService->throw($errors[key($errors)][0]);
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
            'resolve' => function($source, array $arguments) use ($settings, $tokenService, $errorService, $elementsService, $usersService, $permissionsService) {
                $user = $tokenService->getUserFromToken();

                $currentPassword = $arguments['currentPassword'];
                $newPassword = $arguments['newPassword'];
                $confirmPassword = $arguments['confirmPassword'];

                if ($newPassword !== $confirmPassword) {
                    $errorService->throw($settings->invalidPasswordMatch);
                }

                $userPermissions = $permissionsService->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissionsService->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                $user = $usersService->getUserByUsernameOrEmail($user->email);

                if (!$user->authenticate($currentPassword)) {
                    $permissionsService->saveUserPermissions($user->id, $userPermissions);
                    $errorService->throw($settings->invalidPasswordUpdate);
                }

                $permissionsService->saveUserPermissions($user->id, $userPermissions);

                $user->newPassword = $newPassword;

                if (!$elementsService->saveElement($user)) {
                    $errors = $user->getErrors();
                    $errorService->throw($errors[key($errors)][0]);
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
                    'photo' => File::getType(),
                ],
                $userArguments
            ),
            'resolve' => function($source, array $arguments, $context, ResolveInfo $resolveInfo) use ($settings, $tokenService, $errorService, $elementsService, $usersService, $volumesService, $projectConfigService) {
                $user = $tokenService->getUserFromToken();

                $email = $arguments['email'] ?? null;
                $username = $arguments['username'] ?? null;
                $firstName = $arguments['firstName'] ?? null;
                $lastName = $arguments['lastName'] ?? null;
                $preferredLanguage = $arguments['preferredLanguage'] ?? null;

                if ($email) {
                    if ($user->username === $user->email) {
                        $user->username = $email;
                    }

                    $user->email = $email;
                }

                if ($username) {
                    $user->username = $username;
                }

                if ($firstName) {
                    $user->firstName = $firstName;
                }

                if ($lastName) {
                    $user->lastName = $lastName;
                }

                if ($preferredLanguage) {
                    $usersService->saveUserPreferences($user, ['language' => $preferredLanguage]);
                }

                if (array_key_exists('photo', $arguments)) {
                    $photo = $arguments['photo'];

                    if ($photo === null) {
                        $user->setPhoto(null);
                    } else {
                        $volumeUid = $projectConfigService->get('users.photoVolumeUid');

                        if (empty($volumeUid)) {
                            $errorService->throw($settings->volumeNotFound);
                        }

                        $volume = $volumesService->getVolumeByUid($volumeUid);

                        $resolver = new Asset([
                            'volume' => $volumesService->getVolumeByHandle($volume->handle),
                        ]);

                        $newPhoto = $resolver->saveAsset(
                            $source,
                            ['_file' => $photo],
                            $context,
                            $resolveInfo
                        );

                        $user->setPhoto($newPhoto);
                    }
                }

                $this->_saveCustomFields($arguments, $user);

                if (!$elementsService->saveElement($user)) {
                    $errors = $user->getErrors();
                    $errorService->throw($errors[key($errors)][0]);
                }

                return $user;
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

        $this->_saveCustomFields($arguments, $user);

        /** @var ProjectConfig */
        $projectConfigService = Craft::$app->getProjectConfig();
        $requiresVerification = $projectConfigService->get('users.requireEmailVerification');
        $suspendByDefault = $projectConfigService->get('users.suspendByDefault');

        if ($requiresVerification || $suspendByDefault) {
            $user->pending = true;
        }

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        if (!$elementsService->saveElement($user)) {
            $errors = $user->getErrors();
            GraphqlAuthentication::$errorService->throw($errors[key($errors)][0]);
        }

        /** @var Users */
        $usersService = Craft::$app->getUsers();

        if ($userGroup) {
            $usersService->assignUserToGroups($user->id, [$userGroup]);
        }

        $preferredLanguage = $arguments['preferredLanguage'] ?? null;

        if ($preferredLanguage) {
            $usersService->saveUserPreferences($user, ['language' => $preferredLanguage]);
        }

        if ($requiresVerification) {
            $usersService->sendActivationEmail($user);
        }

        $this->_updateLastLogin($user);
        return $user;
    }

    /**
     * Formats authentication/registration mutation responses
     *
     * @param User $user
     * @param int $schemaId
     * @param array $token
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
     * Saves mutation custom fields to user
     *
     * @param array $arguments
     * @param User $user
     */
    protected function _saveCustomFields(array $arguments, User $user)
    {
        $customFields = UserArguments::getContentArguments();

        foreach ($customFields as $key => $customField) {
            if (!array_key_exists($key, $arguments)) {
                continue;
            }

            $value = $arguments[$key];

            if (is_array($customField) && (string) $customField['type'] === '[QueryArgument]' && $value === null) {
                $value = [];
            }

            $user->setFieldValue($key, $value);
        }
    }

    /**
     * Updates user's last login time
     *
     * @param User $user
     */
    protected function _updateLastLogin(User $user)
    {
        /** @var Users */
        $usersService = Craft::$app->getUsers();
        $usersService->handleValidLogin($user);
    }
}

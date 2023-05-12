<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use born05\twofactorauthentication\Plugin as TwoFactorAuth;
use born05\twofactorauthentication\services\Verify;
use craft\base\Component;
use craft\elements\User;
use craft\events\RegisterGqlMutationsEvent;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Gql;
use craft\services\UserPermissions;
use craft\services\Users;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class TwoFactorService extends Component
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
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    /**
     * Registers Two-Factor mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        $settings = GraphqlAuthentication::$settings;

        if (!$settings->allowTwoFactorAuthentication) {
            return;
        }

        $tokenService = GraphqlAuthentication::$tokenService;
        $errorService = GraphqlAuthentication::$errorService;

        /** @var Users */
        $usersService = Craft::$app->getUsers();

        /** @var UserPermissions */
        $permissionsService = Craft::$app->getUserPermissions();

        /** @var Verify */
        $verifyService = TwoFactorAuth::$plugin->verify;

        $event->mutations['generateTwoFactorQrCode'] = [
            'description' => 'Generates Two-Factor QR Code data URI. Returns string.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function ($source, array $arguments) use ($tokenService, $verifyService) {
                $user = $tokenService->getUserFromToken();
                return $verifyService->getUserQRCode($user);
            }
        ];

        $event->mutations['generateTwoFactorSecretCode'] = [
            'description' => 'Generates Two-Factor secret code. Returns string.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function ($source, array $arguments) use ($tokenService, $verifyService) {
                $user = $tokenService->getUserFromToken();
                return $verifyService->getUserSecret($user);
            }
        ];

        $event->mutations['verifyTwoFactor'] = [
            'description' => 'Verifies Two-Factor code. Returns user and token.',
            'type' => Type::nonNull(Auth::getType()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
                'password' => Type::nonNull(Type::string()),
                'code' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService, $usersService, $permissionsService, $verifyService) {
                $email = $arguments['email'];
                $password = $arguments['password'];
                $code = $arguments['code'];
                $user = $usersService->getUserByUsernameOrEmail($email);

                if (!$user = $usersService->getUserByUsernameOrEmail($email)) {
                    $errorService->throw($settings->invalidLogin);
                }

                if (!$verifyService->verify($user, $code)) {
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
                    $permissionsService->saveUserPermissions($user->id, $userPermissions);

                    switch ($user->authError) {
                        case User::AUTH_PASSWORD_RESET_REQUIRED:
                            $usersService->sendPasswordResetEmail($user);
                            $errorService->throw($settings->passwordResetRequired, true);
                            break;

                        case User::AUTH_ACCOUNT_LOCKED:
                            $errorService->throw($settings->accountLocked, true);
                            break;

                        case User::AUTH_ACCOUNT_COOLDOWN:
                            $errorService->throw($settings->accountCooldown, true);
                            break;

                        default:
                            $errorService->throw($settings->invalidLogin);
                            break;
                    }
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

                $usersService->handleValidLogin($user);
                $token = $tokenService->create($user, $schemaId);

                return GraphqlAuthentication::$userService->getResponseFields($user, $schemaId, $token);
            },
        ];

        $event->mutations['disableTwoFactor'] = [
            'description' => 'Disables Two-Factor. Returns boolean.',
            'type' => Type::nonNull(Auth::getType()),
            'args' => [
                'password' => Type::nonNull(Type::string()),
                'confirmPassword' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $errorService, $usersService, $permissionsService, $verifyService) {
                $user = $tokenService->getUserFromToken();
                $user = $usersService->getUserByUsernameOrEmail($user->email);

                $password = $arguments['password'];
                $confirmPassword = $arguments['confirmPassword'];

                if ($password !== $confirmPassword) {
                    $errorService->throw($settings->invalidPasswordMatch);
                }

                $userPermissions = $permissionsService->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissionsService->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                if (!$user->authenticate($password)) {
                    $permissionsService->saveUserPermissions($user->id, $userPermissions);
                    $errorService->throw($settings->invalidLogin);
                }

                $verifyService->disableUser($user);
            }
        ];
    }
}

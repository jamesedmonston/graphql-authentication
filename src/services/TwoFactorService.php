<?php

namespace jamesedmonston\graphqlauthentication\services;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\events\RegisterGqlMutationsEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\records\Authenticator as AuthenticatorRecord;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Gql;
use craft\web\Session;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use PragmaRX\Google2FA\Exceptions\Google2FAException;
use PragmaRX\Google2FA\Google2FA;
use yii\base\Event;
use yii\base\Exception;
use yii\web\ForbiddenHttpException;

class TwoFactorService extends Component
{
    /**
     * @var string The session variable name used to store the authenticator
     * secret while setting up this method.
     */
    public string $secretParam;

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
     * Registers Two-Factor queries
     *
     * @param RegisterGqlQueriesEvent $event
     */
    public function registerGqlQueries(RegisterGqlQueriesEvent $event)
    {
        $settings = GraphqlAuthentication::$settings;

        if (!$settings->allowTwoFactorAuthentication) {
            return;
        }

        $tokenService = GraphqlAuthentication::$tokenService;

        $event->queries['twoFactorEnabled'] = [
            'description' => 'Checks if user has Two-Factor enabled. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function($source, array $arguments) use ($tokenService) {
                $user = $tokenService->getUserFromToken();
                return $this->twoFactorEnabled($user);
            },
        ];
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

        $usersService = Craft::$app->getUsers();
        $permissionsService = Craft::$app->getUserPermissions();

        $event->mutations['generateTwoFactorQrCode'] = [
            'description' => 'Generates Two-Factor QR Code data URI. Returns string.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function($source, array $arguments) use ($tokenService) {
                $user = $tokenService->getUserFromToken();
                return $this->generateQrCode($user);
            },
        ];

        $event->mutations['generateTwoFactorSecretCode'] = [
            'description' => 'Generates Two-Factor secret code. Returns string.',
            'type' => Type::nonNull(Type::string()),
            'args' => [],
            'resolve' => function($source, array $arguments) use ($tokenService) {
                $user = $tokenService->getUserFromToken();
                return $this->secret($user);
            },
        ];

        $event->mutations['verifyTwoFactor'] = [
            'description' => 'Verifies Two-Factor code. Returns user and token.',
            'type' => Type::nonNull(Auth::getType()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
                'password' => Type::nonNull(Type::string()),
                'code' => Type::nonNull(Type::string()),
            ],
            'resolve' => function($source, array $arguments) use ($settings, $tokenService, $errorService, $usersService, $permissionsService) {
                $email = $arguments['email'];
                $password = $arguments['password'];
                $code = $arguments['code'];

                if (!$user = $usersService->getUserByUsernameOrEmail($email)) {
                    $errorService->throw($settings->invalidLogin);
                }

                if (!$this->verify($code, $user)) {
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

                            // no break
                        case User::AUTH_ACCOUNT_LOCKED:
                            $errorService->throw($settings->accountLocked, true);

                            // no break
                        case User::AUTH_ACCOUNT_COOLDOWN:
                            $errorService->throw($settings->accountCooldown, true);

                            // no break
                        default:
                            $errorService->throw($settings->invalidLogin);
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
            'type' => Type::nonNull(Type::boolean()),
            'args' => [
                'password' => Type::nonNull(Type::string()),
                'confirmPassword' => Type::nonNull(Type::string()),
            ],
            'resolve' => function($source, array $arguments) use ($settings, $tokenService, $errorService, $usersService, $permissionsService) {
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

                $this->disableTwoFactor($user);
                return true;
            },
        ];
    }

    /**
     * Methods adapted from /vendor/craftcms/cms/src/auth/methods/TOTP.php
     */

    /**
     * Checks user's 2FA status.
     *
     * @param User $user
     */
    private function twoFactorEnabled(User $user) {
        $secret = $this->secretFromDb($user);
        return (bool) $secret;
    }

    /**
     * Disables user's 2FA.
     *
     * @param User $user
     */
    private function disableTwoFactor(User $user) {
        AuthenticatorRecord::deleteAll([
            'userId' => $user->id,
        ]);
    }

    /**
     * Returns user's 2FA secret from the database.
     *
     * @param User $user
     * @return string|null
     */
    private function secretFromDb(User $user) {
        if (!isset($this->secretParam)) {
            $stateKeyPrefix = md5(sprintf('Craft.%s.%s.%s', Session::class, Craft::$app->id, $user->id));
            $this->secretParam = sprintf('%s__secret', $stateKeyPrefix);
        }

        $record = AuthenticatorRecord::find()
            ->select(['auth2faSecret'])
            ->where(['userId' => $user->id])
            ->one();

        $secret = $record ? $record['auth2faSecret'] : null;
        return $secret;
    }

     /**
     * Returns user's 2FA secret from the database.
     *
     * @param User $user
     * @return string|null
     */
    private function secret(User $user) {
        $google2fa = new Google2FA();
        $secret = self::secretFromDb($user);

        if (empty($secret)) {
            try {
                $secret = $google2fa->generateSecretKey(32);
                Craft::$app->getSession()->set($this->secretParam, $secret);
            } catch (\Exception $e) {
                Craft::$app->getErrorHandler()->logException($e);
            }
        }

        return rtrim(chunk_split($secret, 4, ' '));
    }

    /**
     * Generates and returns a QR code based on given 2fa secret.
     *
     * @param User $user
     * @return string
     */
    private function generateQrCode(User $user) {
        $secret = $this->secret($user);

        $qrCodeUrl = (new Google2FA())->getQRCodeUrl(
            Craft::$app->getSystemName(),
            $user->email,
            $secret,
        );

        $renderer = new ImageRenderer(
            new RendererStyle(150, 0),
            new SvgImageBackEnd()
        );

        return (new Writer($renderer))->writeString($qrCodeUrl);
    }

    /**
     * Stores user's 2fa secret in the database.
     *
     * @param User $user
     * @param string $secret
     * @return void
     * @throws ForbiddenHttpException
     */
    private function storeSecret(User $user, string $secret): void
    {
        /** @var AuthenticatorRecord|null $record */
        $record = AuthenticatorRecord::find()
            ->where(['userId' => $user->id])
            ->one();

        if (!$record) {
            $record = new AuthenticatorRecord();
            $record->userId = $user->id;
        }

        $record->auth2faSecret = $secret;
        // whenever we store the secret, we should ensure the oldTimestamp is accurate too
        $record->oldTimestamp = (new Google2FA())->getTimestamp();
        $record->save();
    }

    /**
     * Returns the totp's old timestamp.
     *
     * @param User $user
     * @return int|null
     */
    private function lastUsedTimestamp(User $user): ?int
    {
        $record = AuthenticatorRecord::find()
            ->select(['oldTimestamp'])
            ->where(['userId' => $user->id])
            ->one();

        if (!$record) {
            return null;
        }

        // old timestamp is the current Unix Timestamp divided by the $keyRegeneration period
        // so we store it as int and don't mess with it
        return $record['oldTimestamp'];
    }

    /**
     * Saves totp's old timestamp.
     *
     * @param User $user
     * @param int $timestamp
     * @return void
     */
    private function storeLastUsedTimestamp(User $user, int $timestamp): void
    {
        /** @var AuthenticatorRecord|null $record */
        $record = AuthenticatorRecord::find()
            ->where(['userId' => $user->id])
            ->one();

        if (!$record) {
            // you shouldn't be able to get here without having a record, so let's throw an exception
            throw new Exception('Couldn\'t find authenticator record.');
        }

        $record->oldTimestamp = $timestamp;
        $record->save();
    }

    /**
     * Verifies user's 2FA code.
     *
     * @param string $code
     * @param User $user
     */
    public function verify(string $code, User $user): bool
    {
        if (!$code) {
            return false;
        }

        $storedSecret = self::secretFromDb($user);
        $secret = $storedSecret ?? Craft::$app->getSession()->get($this->secretParam);

        if (!$secret) {
            return false;
        }

        $google2fa = new Google2FA();
        try {
            $lastUsedTimestamp = $this->lastUsedTimestamp($user);
            $verified = $google2fa->verifyKeyNewer($secret, $code, $lastUsedTimestamp);
        } catch (Google2FAException) {
            return false;
        }

        if (!$verified) {
            return false;
        }

        if (!$storedSecret) {
            $this->storeSecret($user, $secret);
            Craft::$app->getSession()->remove($this->secretParam);
        } else {
            $this->storeLastUsedTimestamp($user, $verified === true ? $google2fa->getTimestamp() : $verified);
        }

        return true;
    }
}

<?php
/**
 * GraphQL Authentication plugin for Craft CMS 3.5
 *
 * GraphQL authentication for your headless Craft CMS applications.
 *
 * @link      https://github.com/jamesedmonston/graphql-authentication
 * @copyright Copyright (c) 2020 James Edmonston
 */

namespace jamesedmonston\graphqlauthentication;

use Craft;
use craft\base\Plugin;
use craft\elements\Entry;
use craft\elements\User;
use craft\events\ModelEvent;
use craft\gql\arguments\elements\Asset as AssetArguments;
use craft\gql\arguments\elements\Entry as EntryArguments;
use craft\gql\GqlEntityRegistry;
use craft\gql\interfaces\elements\Asset as AssetInterface;
use craft\gql\interfaces\elements\Entry as EntryInterface;
use craft\gql\types\generators\UserType;
use craft\models\GqlToken;
use craft\services\Gql;
use DateTime;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\models\Settings;
use jamesedmonston\graphqlauthentication\resolvers\Asset as AssetResolver;
use jamesedmonston\graphqlauthentication\resolvers\Entry as EntryResolver;
use yii\base\Event;
use yii\base\InvalidArgumentException;
use yii\web\BadRequestHttpException;

/**
 * Class GraphqlAuthentication
 *
 * @author    James Edmonston
 * @package   GraphqlAuthentication
 * @since     1.0.0
 *
 */
class GraphqlAuthentication extends Plugin
{
    // Static Properties
    // =========================================================================

    /**
     * @var GraphqlAuthentication
     */
    public static $plugin;

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public $schemaVersion = '1.0.0';

    /**
     * @var bool
     */
    public $hasCpSettings = true;

    /**
     * @var bool
     */
    public $hasCpSection = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        self::$plugin = $this;

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

        Event::on(
            Entry::class,
            Entry::EVENT_BEFORE_SAVE,
            [$this, 'restrictMutations']
        );

        Event::on(
            Entry::class,
            Entry::EVENT_BEFORE_DELETE,
            [$this, 'restrictMutations']
        );
    }

    public function registerGqlQueries(Event $event)
    {
        if (!$this->_isSchemaSet()) {
            return;
        }

        $event->queries['entries'] = [
            'description' => 'This query is used to query for entries.',
            'type' => Type::listOf(EntryInterface::getType()),
            'args' => EntryArguments::getArguments(),
            'resolve' => EntryResolver::class . '::resolve',
        ];

        $event->queries['entry'] = [
            'description' => 'This query is used to query for a single entry.',
            'type' => EntryInterface::getType(),
            'args' => EntryArguments::getArguments(),
            'resolve' => EntryResolver::class . '::resolveOne',
        ];

        $event->queries['entryCount'] = [
            'description' => 'This query is used to return the number of entries.',
            'type' => Type::nonNull(Type::int()),
            'args' => EntryArguments::getArguments(),
            'resolve' => EntryResolver::class . '::resolveCount',
        ];

        $event->queries['assets'] = [
            'description' => 'This query is used to query for assets.',
            'type' => Type::listOf(AssetInterface::getType()),
            'args' => AssetArguments::getArguments(),
            'resolve' => AssetResolver::class . '::resolve',
        ];

        $event->queries['asset'] = [
            'description' => 'This query is used to query for a single asset.',
            'type' => AssetInterface::getType(),
            'args' => AssetArguments::getArguments(),
            'resolve' => AssetResolver::class . '::resolveOne',
        ];

        $event->queries['assetCount'] = [
            'description' => 'This query is used to return the number of assets.',
            'type' => Type::nonNull(Type::int()),
            'args' => AssetArguments::getArguments(),
            'resolve' => AssetResolver::class . '::resolveCount',
        ];

        $event->queries['getUser'] = [
            'description' => 'Gets authenticated user.',
            'type' => UserType::generateType(User::class),
            'args' => [],
            'resolve' => function () {
                $user = $this->getUserFromToken();

                if (!$user) {
                    throw new Error("We couldn't find any matching users");
                }

                return $user;
            },
        ];
    }

    public function registerGqlMutations(Event $event)
    {
        if (!$this->_isSchemaSet()) {
            return;
        }

        $tokenAndUser = Type::nonNull(
            GqlEntityRegistry::createEntity('Auth', new ObjectType([
                'name' => 'Auth',
                'fields' => [
                    'accessToken' => Type::nonNull(Type::string()),
                    'user' => UserType::generateType(User::class),
                ],
            ]))
        );

        $event->mutations['authenticate'] = [
            'description' => 'Logs a user in. Returns user and token.',
            'type' => $tokenAndUser,
            'args' => [
                'email' => Type::nonNull(Type::string()),
                'password' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) {
                $email = $arguments['email'];
                $password = $arguments['password'];
                $user = Craft::$app->getUsers()->getUserByUsernameOrEmail($email);
                $error = "We couldn't log you in with the provided details";

                if (!$user) {
                    throw new Error($error);
                }

                $userPermissions = Craft::$app->getUserPermissions()->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    Craft::$app->getUserPermissions()->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                if (!$user->authenticate($password)) {
                    Craft::$app->getUserPermissions()->saveUserPermissions($user->id, $userPermissions);
                    throw new Error($error);
                }

                Craft::$app->getUserPermissions()->saveUserPermissions($user->id, $userPermissions);

                return [
                    'accessToken' => $this->_generateToken($user),
                    'user' => $user,
                ];
            },
        ];

        $event->mutations['register'] = [
            'description' => 'Registers a user. Returns user and token.',
            'type' => $tokenAndUser,
            'args' => [
                'email' => Type::nonNull(Type::string()),
                'password' => Type::nonNull(Type::string()),
                'firstName' => Type::nonNull(Type::string()),
                'lastName' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) {
                $email = $arguments['email'];
                $password = $arguments['password'];
                $firstName = $arguments['firstName'];
                $lastName = $arguments['lastName'];

                $user = new User();
                $user->username = $email;
                $user->email = $email;
                $user->newPassword = $password;
                $user->firstName = $firstName;
                $user->lastName = $lastName;

                if (!Craft::$app->getElements()->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                if ($this->getSettings()->userGroup) {
                    Craft::$app->getUsers()->assignUserToGroups($user->id, [$this->getSettings()->userGroup]);
                }

                return [
                    'accessToken' => $this->_generateToken($user),
                    'user' => $user,
                ];
            },
        ];

        $event->mutations['forgottenPassword'] = [
            'description' => "Sends a password reset email to the user's email address. Returns success message.",
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'email' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) {
                $email = $arguments['email'];
                $user = Craft::$app->getUsers()->getUserByUsernameOrEmail($email);
                $message = 'You will receive an email if it matches an account in our system';

                if (!$user) {
                    return $message;
                }

                Craft::$app->getUsers()->sendPasswordResetEmail($user);

                return $message;
            },
        ];

        $event->mutations['setPassword'] = [
            'description' => 'Sets password for unauthenticated users. Requires `code` and `id` from Craft reset password email. Returns success message.',
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'password' => Type::nonNull(Type::string()),
                'code' => Type::nonNull(Type::string()),
                'id' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) {
                $password = $arguments['password'];
                $code = $arguments['code'];
                $id = $arguments['id'];

                $user = Craft::$app->getUsers()->getUserByUid($id);

                if (!$user || !Craft::$app->getUsers()->isVerificationCodeValidForUser($user, $code)) {
                    throw new Error('Cannot validate request');
                }

                $user->newPassword = $password;

                if (!Craft::$app->getElements()->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                return 'Successfully saved password';
            },
        ];

        $event->mutations['updatePassword'] = [
            'description' => 'Updates password for authenticated users. Requires access token and current password. Returns success message.',
            'type' => Type::nonNull(Type::string()),
            'args' => [
                'currentPassword' => Type::nonNull(Type::string()),
                'newPassword' => Type::nonNull(Type::string()),
                'confirmPassword' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) {
                $user = $this->getUserFromToken();
                $error = "We couldn't update the password with the provided details";

                if (!$user) {
                    throw new Error($error);
                }

                $newPassword = $arguments['newPassword'];
                $confirmPassword = $arguments['confirmPassword'];

                if ($newPassword !== $confirmPassword) {
                    throw new Error('New passwords do not match');
                }

                $currentPassword = $arguments['currentPassword'];

                if (!$user->authenticate($currentPassword)) {
                    throw new Error($error);
                }

                $user->newPassword = $newPassword;

                if (!Craft::$app->getElements()->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                return 'Successfully updated password';
            },
        ];

        $event->mutations['updateUser'] = [
            'description' => 'Updates authenticated user. Returns user.',
            'type' => UserType::generateType(User::class),
            'args' => [
                'email' => Type::string(),
                'firstName' => Type::string(),
                'lastName' => Type::string(),
            ],
            'resolve' => function ($source, array $arguments) {
                $user = $this->getUserFromToken();

                if (!$user) {
                    throw new Error("We couldn't update the user with the provided details");
                }

                $email = $arguments['email'];
                $firstName = $arguments['firstName'];
                $lastName = $arguments['lastName'];

                if ($email) {
                    $user->username = $email;
                    $user->email = $email;
                }

                if ($firstName) {
                    $user->firstName = $firstName;
                }

                if ($lastName) {
                    $user->lastName = $lastName;
                }

                if (!Craft::$app->getElements()->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                return $user;
            },
        ];

        $event->mutations['deleteCurrentToken'] = [
            'description' => 'Deletes authenticated user access token. Useful for logging out of current device. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () {
                $token = $this->_getHeaderToken();

                if (!$token) {
                    throw new Error("We couldn't find any matching tokens");
                }

                Craft::$app->getGql()->deleteTokenById($token->id);

                return true;
            },
        ];

        $event->mutations['deleteAllTokens'] = [
            'description' => 'Deletes all access tokens belonging to the authenticated user. Useful for logging out of all devices. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () {
                $user = $this->getUserFromToken();
                $error = "We couldn't find any matching tokens";

                if (!$user) {
                    throw new Error($error);
                }

                $savedTokens = Craft::$app->getGql()->getTokens();

                if (!$savedTokens || !count($savedTokens)) {
                    throw new Error($error);
                }

                foreach ($savedTokens as $savedToken) {
                    if (strpos($savedToken->name, "user-{$user->id}") !== false) {
                        Craft::$app->getGql()->deleteTokenById($savedToken->id);
                    }
                }

                return true;
            },
        ];
    }

    public function restrictMutations(ModelEvent $event)
    {
        if (!Craft::$app->getRequest()->getBodyParam('query')) {
            return;
        }

        $user = $this->getUserFromToken();
        $fields = $event->sender->getFieldValues();
        $error = "User doesn't have permission to perform this mutation";

        foreach ($fields as $key => $field) {
            if (!isset($field->elementType) || !isset($field->id)) {
                continue;
            }

            if ($field->elementType === 'craft\\elements\\Entry') {
                $entry = Craft::$app->getElements()->getElementById($field->id[0]);

                if (!$entry) {
                    continue;
                }

                $authorOnlySections = $this->getSettings()->queries;

                if ((string) $event->sender->authorId === (string) $user->id) {
                    continue;
                }

                foreach ($authorOnlySections as $section => $value) {
                    if (!(bool) $value) {
                        continue;
                    }

                    if ($entry->sectionId !== Craft::$app->getSections()->getSectionByHandle($section)->id) {
                        continue;
                    }

                    throw new Error($error);
                }
            }

            if ($field->elementType === 'craft\\elements\\Asset') {
                $asset = Craft::$app->getAssets()->getAssetById($field->id[0]);

                if (!$asset || !$asset->uploaderId) {
                    continue;
                }

                if ((string) $asset->uploader !== (string) $user->id) {
                    throw new Error($error);
                }
            }
        }

        if ($event->isNew) {
            $event->sender->authorId = $user->id;
            return;
        }

        $authorOnlySections = $this->getSettings()->mutations ?? [];
        $entrySection = Craft::$app->getSections()->getSectionById($event->sender->sectionId)->handle;

        if (in_array($entrySection, array_keys($authorOnlySections))) {
            foreach ($authorOnlySections as $key => $value) {
                if (!(bool) $value || $key !== $entrySection) {
                    continue;
                }

                if ((string) $event->sender->authorId !== (string) $user->id) {
                    throw new Error($error);
                }
            }
        }
    }

    public function getUserFromToken(): User
    {
        return Craft::$app->getUsers()->getUserById($this->_extractUserIdFromToken($this->_getHeaderToken()));
    }

    // Protected Methods
    // =========================================================================

    protected function _isSchemaSet(): bool
    {
        return (bool) isset($this->getSettings()->schemaId);
    }

    protected function _getHeaderToken(): GqlToken
    {
        $request = Craft::$app->getRequest();
        $requestHeaders = $request->getHeaders();

        foreach ($requestHeaders->get('authorization', [], false) as $authHeader) {
            $authValues = array_map('trim', explode(',', $authHeader));

            foreach ($authValues as $authValue) {
                if (preg_match('/^Bearer\s+(.+)$/i', $authValue, $matches)) {
                    try {
                        $token = Craft::$app->getGql()->getTokenByAccessToken($matches[1]);
                    } catch (InvalidArgumentException $e) {
                        throw new InvalidArgumentException($e);
                    }

                    if (!$token) {
                        throw new BadRequestHttpException('Invalid Authorization header');
                    }

                    break 2;
                }
            }
        }

        if (!isset($token)) {
            throw new BadRequestHttpException('Missing Authorization header');
        }

        if (strtotime(date('y-m-d H:i:s')) >= strtotime($token->expiryDate->format('y-m-d H:i:s'))) {
            throw new BadRequestHttpException('Invalid Authorization header');
        }

        return $token;
    }

    protected function _generateToken(User $user): string
    {
        if (!$this->_isSchemaSet()) {
            throw new Error('No schema has been created');
        }

        $settings = $this->getSettings();
        $accessToken = Craft::$app->getSecurity()->generateRandomString(32);
        $time = time();

        $fields = [
            'name' => "user-{$user->id}-{$time}",
            'accessToken' => $accessToken,
            'enabled' => true,
            'schemaId' => $settings->schemaId,
        ];

        if ($settings->expiration) {
            $fields['expiryDate'] = (new DateTime())->modify("+ {$settings->expiration}");
        }

        $token = new GqlToken($fields);

        if (!Craft::$app->getGql()->saveToken($token)) {
            throw new Error(json_encode($token->getErrors()));
        }

        return $accessToken;
    }

    protected function _extractUserIdFromToken(GqlToken $token): string
    {
        return explode('-', $token->name)[1];
    }

    protected function createSettingsModel()
    {
        return new Settings();
    }

    protected function settingsHtml()
    {
        $settings = $this->getSettings();
        $userGroups = Craft::$app->getUserGroups()->getAllGroups();
        $schemas = Craft::$app->getGql()->getSchemas();
        $publicSchema = Craft::$app->getGql()->getPublicSchema();

        $userOptions = [
            [
                'label' => '',
                'value' => '',
            ]
        ];

        foreach ($userGroups as $userGroup) {
            $userOptions[] = [
                'label' => $userGroup->name,
                'value' => $userGroup->id,
            ];
        }

        $schemaOptions = [
            [
                'label' => '',
                'value' => '',
            ]
        ];

        foreach ($schemas as $schema) {
            if ($publicSchema && $schema->id === $publicSchema->id) {
                continue;
            }

            $schemaOptions[] = [
                'label' => $schema->name,
                'value' => $schema->id,
            ];
        }

        $queries = null;
        $mutations = null;

        if ($settings->schemaId) {
            $selectedSchema = Craft::$app->getGql()->getSchemaById($settings->schemaId);
            $entryTypes = Craft::$app->getSections()->getAllEntryTypes();
            $queries = [];
            $mutations = [];

            $scopes = array_filter($selectedSchema->scope, function ($key) {
                return strpos($key, 'entrytypes') !== false;
            });

            foreach ($scopes as $scope) {
                $scopeId = explode(':', explode('.', $scope)[1])[0];

                $entryType = array_values(array_filter($entryTypes, function ($type) use ($scopeId) {
                    return $type['uid'] === $scopeId;
                }))[0];

                $name = $entryType->name;
                $handle = $entryType->handle;

                if (strpos($scope, ':read') !== false) {
                    if (isset($queries[$name])) {
                        continue;
                    }

                    $queries[$name] = [
                        'label' => $name,
                        'handle' => $handle,
                    ];

                    continue;
                }

                if (isset($mutations[$name])) {
                    continue;
                }

                $mutations[$name] = [
                    'label' => $name,
                    'handle' => $handle,
                ];
            }
        }

        return Craft::$app->getView()->renderTemplate('graphql-authentication/index', [
            'settings' => $settings,
            'userOptions' => $userOptions,
            'schemaOptions' => $schemaOptions,
            'queries' => $queries,
            'mutations' => $mutations,
        ]);
    }
}
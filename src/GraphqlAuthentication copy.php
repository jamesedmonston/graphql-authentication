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
use craft\events\ExecuteGqlQueryEvent;
use craft\events\ModelEvent;
use craft\gql\GqlEntityRegistry;
use craft\gql\types\generators\UserType;
use craft\models\GqlToken;
use craft\services\Gql;
use DateTime;
use GraphQL\Error\Error;
use GraphQL\GraphQL;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\models\Settings;
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
            Gql::class,
            Gql::EVENT_BEFORE_EXECUTE_GQL_QUERY,
            [$this, 'restrictQueries']
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

        $event->queries['getUser'] = [
            'type' => UserType::generateType(User::class),
            'description' => 'Gets authenticated user.',
            'args' => [],
            'resolve' => function () {
                $token = $this->_getHeaderToken();
                $user = Craft::$app->getUsers()->getUserById($this->_extractUserId($token));

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
            'type' => $tokenAndUser,
            'description' => 'Logs a user in. Returns user and token.',
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
            'type' => $tokenAndUser,
            'description' => 'Registers a user. Returns user and token.',
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
            'type' => Type::nonNull(Type::string()),
            'description' => "Sends a password reset email to the user's email address. Returns success message.",
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
            'type' => Type::nonNull(Type::string()),
            'description' => 'Sets password for unauthenticated users. Requires `code` and `id` from Craft reset password email. Returns success message.',
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
            'type' => Type::nonNull(Type::string()),
            'description' => 'Updates password for authenticated users. Requires access token and current password. Returns success message.',
            'args' => [
                'currentPassword' => Type::nonNull(Type::string()),
                'newPassword' => Type::nonNull(Type::string()),
                'confirmPassword' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) {
                $token = $this->_getHeaderToken();
                $user = Craft::$app->getUsers()->getUserById($this->_extractUserId($token));
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
            'type' => UserType::generateType(User::class),
            'description' => 'Updates authenticated user. Returns user.',
            'args' => [
                'email' => Type::string(),
                'firstName' => Type::string(),
                'lastName' => Type::string(),
            ],
            'resolve' => function ($source, array $arguments) {
                $token = $this->_getHeaderToken();
                $user = Craft::$app->getUsers()->getUserById($this->_extractUserId($token));

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
            'type' => Type::nonNull(Type::boolean()),
            'description' => 'Deletes authenticated user access token. Useful for logging out of current device. Returns boolean.',
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
            'type' => Type::nonNull(Type::boolean()),
            'description' => 'Deletes all access tokens belonging to the authenticated user. Useful for logging out of all devices. Returns boolean.',
            'args' => [],
            'resolve' => function () {
                $token = $this->_getHeaderToken();
                $user = Craft::$app->getUsers()->getUserById($this->_extractUserId($token));
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

    public function restrictQueries(ExecuteGqlQueryEvent $event)
    {
        $query = $event->query;

        $publicMutations = [
            '/authenticate\(/',
            '/authenticate\s+\(/',
            '/register\(/',
            '/register\s+\(/',
            '/forgottenPassword\(/',
            '/forgottenPassword\s+\(/',
            '/setPassword\(/',
            '/setPassword\s+\(/'
        ];

        $isPublicMutation = false;

        foreach ($publicMutations as $publicMutation) {
            preg_match($publicMutation, $query, $matches);

            if (count($matches)) {
                $isPublicMutation = true;
            }
        }

        if ($isPublicMutation) {
            return;
        }

        $token = $this->_getHeaderToken();
        $userId = $this->_extractUserId($token);
        $settings = $this->getSettings();
        $variables = $event->variables;

        // add `authorId` to `entry` queries
        $queryRewrites = [
            ['/entries\(/', 'entries('],
            ['/entries\s+\(/', 'entries('],
            ['/entry\(/', 'entry('],
            ['/entry\s+\(/', 'entry('],
            ['/entryCount\(/', 'entryCount('],
            ['/entryCount\s+\(/', 'entryCount('],
        ];

        $authorOnlySections = $settings->queries ?? [];

        foreach ($queryRewrites as $queryRewrite) {
            preg_match($queryRewrite[0], $query, $matches);

            if (!count($matches)) {
                continue;
            }

            // if (!isset($variables['section']) && !isset($variables['sectionId'])) {
            //     throw new Error('Query must supply either a `section` or `sectionId` variable');
            // }

            foreach ($authorOnlySections as $section => $value) {
                if (!(bool) $value) {
                    continue;
                }

                if (isset($variables['section']) && trim($variables['section']) !== $section) {
                    continue;
                }

                if (isset($variables['sectionId']) && trim((string) $variables['sectionId']) !== Craft::$app->getSections()->getSectionByHandle($section)->id) {
                    continue;
                }

                $query = preg_replace($queryRewrite[0], "{$queryRewrite[1]}authorId:{$userId},", $query);
            }
        }

        // always add `authorId` to empty `entry` queries
        $fallbackRewrites = [
            ['/entries\{/', 'entries'],
            ['/entries\s+\{/', 'entries'],
            ['/entry\{/', 'entry'],
            ['/entry\s+\{/', 'entry'],
        ];

        foreach ($fallbackRewrites as $fallbackRewrite) {
            preg_match($fallbackRewrite[0], $query, $matches);

            if (!count($matches)) {
                continue;
            }

            $query = preg_replace($fallbackRewrite[0], "{$fallbackRewrite[1]}(authorId:{$userId}) {", $query);
        }

        // always add `authorId` to empty `entryCount` queries
        $fallbackRewrites = [
            '/entryCount}/',
            '/entryCount\s+}/',
        ];

        foreach ($fallbackRewrites as $fallbackRewrite) {
            preg_match($fallbackRewrite, $query, $matches);

            if (!count($matches)) {
                continue;
            }

            $query = preg_replace($fallbackRewrite, "entryCount(authorId:{$userId})}", $query);
        }

        // add `uploader` to `asset` queries
        $queryRewrites = [
            ['/assets\(/', 'assets('],
            ['/assets\s+\(/', 'assets('],
            ['/asset\(/', 'asset('],
            ['/asset\s+\(/', 'asset('],
            ['/assetCount\(/', 'assetCount('],
            ['/assetCount\s+\(/', 'assetCount('],
        ];

        foreach ($queryRewrites as $queryRewrite) {
            preg_match($queryRewrite[0], $query, $matches);

            if (!count($matches)) {
                continue;
            }

            $query = preg_replace($queryRewrite[0], "{$queryRewrite[1]}uploader:{$userId},", $query);
        }

        // always add `uploader` to empty `asset` queries
        $fallbackRewrites = [
            ['/assets\{/', 'assets'],
            ['/assets\s+\{/', 'assets'],
            ['/asset\{/', 'asset'],
            ['/asset\s+\{/', 'asset'],
        ];

        foreach ($fallbackRewrites as $fallbackRewrite) {
            preg_match($fallbackRewrite[0], $query, $matches);

            if (!count($matches)) {
                continue;
            }

            $query = preg_replace($fallbackRewrite[0], "{$fallbackRewrite[1]}(uploader:{$userId}) {", $query);
        }

        // always add `uploader` to empty `assetCount` queries
        $fallbackRewrites = [
            '/assetCount}/',
            '/assetCount\s+}/',
        ];

        foreach ($fallbackRewrites as $fallbackRewrite) {
            preg_match($fallbackRewrite, $query, $matches);

            if (!count($matches)) {
                continue;
            }

            $query = preg_replace($fallbackRewrite, "assetCount(uploader:{$userId})}", $query);
        }

        $event->result = [$query];

        // $event->result = GraphQL::executeQuery(
        //     Craft::$app->getGql()->getSchemaDef($token->getSchema()),
        //     $query,
        //     $event->rootValue,
        //     $event->context,
        //     $event->variables,
        //     $event->operationName,
        //     null,
        //     Craft::$app->getGql()->getValidationRules(false)
        // )->toArray(false);

        // $event->result = Craft::$app->getGql()->executeQuery($token->getSchema(), $query, $variables, $event->operationName, false)->toArray(false);
    }

    public function restrictMutations(ModelEvent $event)
    {
        if (!Craft::$app->getRequest()->getBodyParam('query')) {
            return;
        }

        $token = $this->_getHeaderToken();
        $userId = $this->_extractUserId($token);

        if ($event->isNew) {
            $event->sender->authorId = $userId;
            return;
        }

        $authorOnlySections = $this->getSettings()->mutations ?? [];
        $entrySection = Craft::$app->getSections()->getSectionById($event->sender->sectionId)->handle;

        if (in_array($entrySection, array_keys($authorOnlySections))) {
            foreach ($authorOnlySections as $key => $value) {
                if (!(bool) $value || $key !== $entrySection) {
                    continue;
                }

                if ($userId !== $event->sender->authorId) {
                    throw new Error("User doesn't have permission to perform this mutation");
                }
            }
        }
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

    protected function _extractUserId(GqlToken $token): string
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

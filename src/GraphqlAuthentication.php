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
use craft\elements\Asset;
use craft\elements\Entry;
use craft\elements\User;
use craft\events\ModelEvent;
use craft\gql\arguments\elements\Asset as AssetArguments;
use craft\gql\arguments\elements\Entry as EntryArguments;
use craft\gql\arguments\elements\User as UserArguments;
use craft\gql\GqlEntityRegistry;
use craft\gql\interfaces\elements\Asset as AssetInterface;
use craft\gql\interfaces\elements\Entry as EntryInterface;
use craft\gql\types\generators\UserType;
use craft\helpers\DateTimeHelper;
use craft\helpers\StringHelper;
use craft\helpers\UrlHelper;
use craft\models\GqlToken;
use craft\records\User as UserRecord;
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

const INVALID_HEADER = 'Invalid Authorization Header';
const INVALID_LOGIN = "We couldn't log you in with the provided details";
const INVALID_PASSWORD_UPDATE = "We couldn't update the password with the provided details";
const INVALID_USER_UPDATE = "We couldn't update the user with the provided details";
const INVALID_REQUEST = 'Cannot validate request';
const INVALID_PASSWORD_MATCH = 'New passwords do not match';
const INVALID_SCHEMA = 'No schema has been created';
const FORBIDDEN_MUTATION = "User doesn't have permission to perform this mutation";
const TOKEN_NOT_FOUND = "We couldn't find any matching tokens";
const USER_NOT_FOUND = "We couldn't find any matching users";
const ENTRY_NOT_FOUND = "We couldn't find any matching entries";
const ASSET_NOT_FOUND = "We couldn't find any matching assets";

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
            [$this, 'registerGqlQueries'],
        );

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations'],
        );

        Event::on(
            Entry::class,
            Entry::EVENT_BEFORE_SAVE,
            function (ModelEvent $event) {
                $this->restrictMutationFields($event);
                $this->ensureEntryMutationAllowed($event);
            },
        );

        Event::on(
            Entry::class,
            Entry::EVENT_BEFORE_DELETE,
            [$this, 'ensureEntryMutationAllowed'],
        );

        Event::on(
            Asset::class,
            Asset::EVENT_BEFORE_SAVE,
            function (ModelEvent $event) {
                $this->restrictMutationFields($event);
                $this->ensureAssetMutationAllowed($event);
            },
        );

        Event::on(
            Asset::class,
            Asset::EVENT_BEFORE_DELETE,
            [$this, 'ensureAssetMutationAllowed'],
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
                    throw new Error(USER_NOT_FOUND);
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

        $elements = Craft::$app->getElements();
        $users = Craft::$app->getUsers();
        $permissions = Craft::$app->getUserPermissions();
        $gql = Craft::$app->getGql();
        $settings = $this->getSettings();

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
            'resolve' => function ($source, array $arguments) use ($users, $permissions) {
                $email = $arguments['email'];
                $password = $arguments['password'];
                $user = $users->getUserByUsernameOrEmail($email);

                if (!$user) {
                    throw new Error(INVALID_LOGIN);
                }

                $userPermissions = $permissions->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissions->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                if (!$user->authenticate($password)) {
                    $permissions->saveUserPermissions($user->id, $userPermissions);
                    throw new Error(INVALID_LOGIN);
                }

                $permissions->saveUserPermissions($user->id, $userPermissions);

                $now = DateTimeHelper::currentUTCDateTime();
                $userRecord = UserRecord::findOne($user->id);
                $userRecord->lastLoginDate = $now;
                $userRecord->save();

                return [
                    'accessToken' => $this->_generateToken($user),
                    'user' => $user,
                ];
            },
        ];

        $event->mutations['register'] = [
            'description' => 'Registers a user. Returns user and token.',
            'type' => $tokenAndUser,
            'args' => array_merge(
                [
                    'email' => Type::nonNull(Type::string()),
                    'password' => Type::nonNull(Type::string()),
                    'firstName' => Type::nonNull(Type::string()),
                    'lastName' => Type::nonNull(Type::string()),
                ],
                UserArguments::getContentArguments(),
            ),
            'resolve' => function ($source, array $arguments) use ($elements, $users, $settings) {
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

                $customFields = UserArguments::getContentArguments();

                foreach ($customFields as $key) {
                    if (!isset($arguments[$key]) || !count($arguments[$key])) {
                        continue;
                    }

                    $user->{$key} = $arguments[$key][0];
                }

                if (!$elements->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                if ($settings->userGroup) {
                    $users->assignUserToGroups($user->id, [$settings->userGroup]);
                }

                $now = DateTimeHelper::currentUTCDateTime();
                $userRecord = UserRecord::findOne($user->id);
                $userRecord->lastLoginDate = $now;
                $userRecord->save();

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
            'resolve' => function ($source, array $arguments) use ($users) {
                $email = $arguments['email'];
                $user = $users->getUserByUsernameOrEmail($email);
                $message = 'You will receive an email if it matches an account in our system';

                if (!$user) {
                    return $message;
                }

                $users->sendPasswordResetEmail($user);

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
            'resolve' => function ($source, array $arguments) use ($elements, $users) {
                $password = $arguments['password'];
                $code = $arguments['code'];
                $id = $arguments['id'];

                $user = $users->getUserByUid($id);

                if (!$user || !$users->isVerificationCodeValidForUser($user, $code)) {
                    throw new Error(INVALID_REQUEST);
                }

                $user->newPassword = $password;

                if (!$elements->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                return 'Successfully saved password';
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
            'resolve' => function ($source, array $arguments) use ($elements, $permissions) {
                $user = $this->getUserFromToken();

                if (!$user) {
                    throw new Error(INVALID_PASSWORD_UPDATE);
                }

                $newPassword = $arguments['newPassword'];
                $confirmPassword = $arguments['confirmPassword'];

                if ($newPassword !== $confirmPassword) {
                    throw new Error(INVALID_PASSWORD_MATCH);
                }

                $currentPassword = $arguments['currentPassword'];
                $userPermissions = $permissions->getPermissionsByUserId($user->id);

                if (!in_array('accessCp', $userPermissions)) {
                    $permissions->saveUserPermissions($user->id, array_merge($userPermissions, ['accessCp']));
                }

                if (!$user->authenticate($currentPassword)) {
                    $permissions->saveUserPermissions($user->id, $userPermissions);
                    throw new Error(INVALID_PASSWORD_UPDATE);
                }

                $permissions->saveUserPermissions($user->id, $userPermissions);

                $user->newPassword = $newPassword;

                if (!$elements->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                return 'Successfully updated password';
            },
        ];

        $event->mutations['updateUser'] = [
            'description' => 'Updates authenticated user. Returns user.',
            'type' => UserType::generateType(User::class),
            'args' => array_merge(
                [
                    'email' => Type::string(),
                    'firstName' => Type::string(),
                    'lastName' => Type::string(),
                ],
                UserArguments::getContentArguments(),
            ),
            'resolve' => function ($source, array $arguments) use ($elements) {
                $user = $this->getUserFromToken();

                if (!$user) {
                    throw new Error(INVALID_USER_UPDATE);
                }

                if (isset($arguments['email'])) {
                    $user->username = $arguments['email'];
                    $user->email = $arguments['email'];
                }

                if (isset($arguments['firstName'])) {
                    $user->firstName = $arguments['firstName'];
                }

                if (isset($arguments['lastName'])) {
                    $user->lastName = $arguments['lastName'];
                }

                $customFields = UserArguments::getContentArguments();

                foreach ($customFields as $key) {
                    if (!isset($arguments[$key]) || !count($arguments[$key])) {
                        continue;
                    }

                    $user->{$key} = $arguments[$key][0];
                }

                if (!$elements->saveElement($user)) {
                    throw new Error(json_encode($user->getErrors()));
                }

                return $user;
            },
        ];

        $event->mutations['deleteCurrentToken'] = [
            'description' => 'Deletes authenticated user access token. Useful for logging out of current device. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () use ($gql) {
                $token = $this->_getHeaderToken();

                if (!$token) {
                    throw new Error(TOKEN_NOT_FOUND);
                }

                $gql->deleteTokenById($token->id);

                return true;
            },
        ];

        $event->mutations['deleteAllTokens'] = [
            'description' => 'Deletes all access tokens belonging to the authenticated user. Useful for logging out of all devices. Returns boolean.',
            'type' => Type::nonNull(Type::boolean()),
            'args' => [],
            'resolve' => function () use ($gql) {
                $user = $this->getUserFromToken();

                if (!$user) {
                    throw new Error(TOKEN_NOT_FOUND);
                }

                $savedTokens = $gql->getTokens();

                if (!$savedTokens || !count($savedTokens)) {
                    throw new Error(TOKEN_NOT_FOUND);
                }

                foreach ($savedTokens as $savedToken) {
                    if (StringHelper::contains($savedToken->name, "user-{$user->id}")) {
                        $gql->deleteTokenById($savedToken->id);
                    }
                }

                return true;
            },
        ];
    }

    public function restrictMutationFields(ModelEvent $event)
    {
        if (!Craft::$app->getRequest()->getBodyParam('query') || $this->isGraphiqlRequest()) {
            return;
        }

        $fields = $event->sender->getFieldValues();

        foreach ($fields as $field) {
            if (!isset($field->elementType)) {
                continue;
            }

            if ($field->elementType !== 'craft\\elements\\MatrixBlock' && !$field->id) {
                continue;
            }

            switch ($field->elementType) {
                case 'craft\\elements\\Entry':
                    foreach ($field->id as $id) {
                        $this->_ensureValidEntry($id);
                    }
                    break;

                case 'craft\\elements\\Asset':
                    foreach ($field->id as $id) {
                        $this->_ensureValidAsset($id);
                    }
                    break;

                case 'craft\\elements\\MatrixBlock':
                    foreach ($field as $matrixBlock) {
                        foreach ($matrixBlock as $key => $value) {
                            if (!$value) {
                                continue;
                            }

                            $matrixField = $matrixBlock[$key];

                            if (!isset($matrixField->elementType) || !$matrixField->id) {
                                continue;
                            }

                            switch ($matrixField->elementType) {
                                case 'craft\\elements\\Entry':
                                    foreach ($matrixField->id as $id) {
                                        $this->_ensureValidEntry($id);
                                    }
                                    break;

                                case 'craft\\elements\\Asset':
                                    foreach ($matrixField->id as $id) {
                                        $this->_ensureValidAsset($id);
                                    }
                                    break;

                                default:
                                    break;
                            }
                        }
                    }
                    break;

                default:
                    break;
            }
        }
    }

    public function ensureEntryMutationAllowed(ModelEvent $event)
    {
        if (!Craft::$app->getRequest()->getBodyParam('query') || $this->isGraphiqlRequest()) {
            return;
        }

        $user = $this->getUserFromToken();

        if ($event->isNew) {
            $event->sender->authorId = $user->id;
            return;
        }

        $authorOnlySections = $this->getSettings()->entryMutations ?? [];
        $entrySection = Craft::$app->getSections()->getSectionById($event->sender->sectionId)->handle;

        if (!in_array($entrySection, array_keys($authorOnlySections))) {
            return;
        }

        foreach ($authorOnlySections as $section => $value) {
            if (!(bool) $value || $section !== $entrySection) {
                continue;
            }

            if ((string) $event->sender->authorId !== (string) $user->id) {
                throw new Error(FORBIDDEN_MUTATION);
            }
        }
    }

    public function ensureAssetMutationAllowed(ModelEvent $event)
    {
        if (!Craft::$app->getRequest()->getBodyParam('query') || $this->isGraphiqlRequest()) {
            return;
        }

        $user = $this->getUserFromToken();

        if ($event->isNew) {
            $event->sender->uploaderId = $user->id;
            return;
        }

        $authorOnlyVolumes = $this->getSettings()->assetMutations ?? [];
        $assetVolume = Craft::$app->getVolumes()->getVolumeById($event->sender->volumeId)->handle;

        if (!in_array($assetVolume, array_keys($authorOnlyVolumes))) {
            return;
        }

        foreach ($authorOnlyVolumes as $volume => $value) {
            if (!(bool) $value || $volume !== $assetVolume) {
                continue;
            }

            if ((string) $event->sender->uploaderId !== (string) $user->id) {
                throw new Error(FORBIDDEN_MUTATION);
            }
        }
    }

    public function getUserFromToken(): User
    {
        return Craft::$app->getUsers()->getUserById($this->_extractUserIdFromToken($this->_getHeaderToken()));
    }

    public function isGraphiqlRequest(): bool
    {
        return StringHelper::contains(Craft::$app->getRequest()->getReferrer(), UrlHelper::cpUrl() . '/graphiql');
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
                        throw new BadRequestHttpException(INVALID_HEADER);
                    }

                    break 2;
                }
            }
        }

        if (!isset($token)) {
            throw new BadRequestHttpException(INVALID_HEADER);
        }

        if (strtotime(date('y-m-d H:i:s')) >= strtotime($token->expiryDate->format('y-m-d H:i:s'))) {
            throw new BadRequestHttpException(INVALID_HEADER);
        }

        return $token;
    }

    protected function _generateToken(User $user): string
    {
        if (!$this->_isSchemaSet()) {
            throw new Error(INVALID_SCHEMA);
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

    protected function _ensureValidEntry(int $id)
    {
        $entry = Craft::$app->getElements()->getElementById($id);

        if (!$entry) {
            throw new Error(ENTRY_NOT_FOUND);
        }

        if (!$entry->authorId) {
            return;
        }

        $user = $this->getUserFromToken();

        if ((string) $entry->authorId === (string) $user->id) {
            return;
        }

        $scope = $this->_getHeaderToken()->getScope();

        if (!in_array("sections.{$entry->section->uid}:read", $scope)) {
            throw new Error(FORBIDDEN_MUTATION);
        }

        $sections = Craft::$app->getSections();
        $authorOnlySections = $this->getSettings()->entryQueries ?? [];

        foreach ($authorOnlySections as $section => $value) {
            if (!(bool) $value) {
                continue;
            }

            if ($entry->sectionId !== $sections->getSectionByHandle($section)->id) {
                continue;
            }

            throw new Error(FORBIDDEN_MUTATION);
        }
    }

    protected function _ensureValidAsset(int $id)
    {
        $asset = Craft::$app->getAssets()->getAssetById($id);

        if (!$asset) {
            throw new Error(ASSET_NOT_FOUND);
        }

        if (!$asset->uploaderId) {
            return;
        }

        $user = $this->getUserFromToken();

        if ((string) $asset->uploaderId === (string) $user->id) {
            return;
        }

        $scope = $this->_getHeaderToken()->getScope();

        if (!in_array("volumes.{$asset->volume->uid}:read", $scope)) {
            throw new Error(FORBIDDEN_MUTATION);
        }

        $volumes = Craft::$app->getVolumes()->getAllVolumes();
        $authorOnlyVolumes = $this->getSettings()->assetQueries ?? [];

        foreach ($authorOnlyVolumes as $volume => $value) {
            if (!(bool) $value) {
                continue;
            }

            if ($asset->volumeId !== $volumes->getVolumeByHandle($volume)->id) {
                continue;
            }

            throw new Error(FORBIDDEN_MUTATION);
        }
    }

    protected function createSettingsModel()
    {
        return new Settings();
    }

    protected function settingsHtml()
    {
        $gql = Craft::$app->getGql();
        $sections = Craft::$app->getSections()->getAllSections();
        $volumes = Craft::$app->getVolumes()->getAllVolumes();
        $settings = $this->getSettings();
        $userGroups = Craft::$app->getUserGroups()->getAllGroups();
        $schemas = $gql->getSchemas();
        $publicSchema = $gql->getPublicSchema();

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

        $entryQueries = null;
        $entryMutations = null;
        $assetQueries = null;
        $assetMutations = null;

        if ($settings->schemaId) {
            $selectedSchema = $gql->getSchemaById($settings->schemaId);

            $entryQueries = [];
            $entryMutations = [];

            $scopes = array_filter($selectedSchema->scope, function ($key) {
                return StringHelper::contains($key, 'sections');
            });

            foreach ($scopes as $scope) {
                $scopeId = explode(':', explode('.', $scope)[1])[0];

                $section = array_values(array_filter($sections, function ($type) use ($scopeId) {
                    return $type['uid'] === $scopeId;
                }))[0];

                if ($section->type === 'single') {
                    continue;
                }

                $name = $section->name;
                $handle = $section->handle;

                if (StringHelper::contains($scope, ':read')) {
                    if (isset($entryQueries[$name])) {
                        continue;
                    }

                    $entryQueries[$name] = [
                        'label' => $name,
                        'handle' => $handle,
                    ];

                    continue;
                }

                if (isset($entryMutations[$name])) {
                    continue;
                }

                $entryMutations[$name] = [
                    'label' => $name,
                    'handle' => $handle,
                ];
            }

            $assetQueries = [];
            $assetMutations = [];

            $scopes = array_filter($selectedSchema->scope, function ($key) {
                return StringHelper::contains($key, 'volumes');
            });

            foreach ($scopes as $scope) {
                $scopeId = explode(':', explode('.', $scope)[1])[0];

                $volume = array_values(array_filter($volumes, function ($type) use ($scopeId) {
                    return $type['uid'] === $scopeId;
                }))[0];

                $name = $volume->name;
                $handle = $volume->handle;

                if (StringHelper::contains($scope, ':read')) {
                    if (isset($assetQueries[$name])) {
                        continue;
                    }

                    $assetQueries[$name] = [
                        'label' => $name,
                        'handle' => $handle,
                    ];

                    continue;
                }

                if (isset($assetMutations[$name])) {
                    continue;
                }

                $assetMutations[$name] = [
                    'label' => $name,
                    'handle' => $handle,
                ];
            }
        }

        return Craft::$app->getView()->renderTemplate('graphql-authentication/index', [
            'settings' => $settings,
            'userOptions' => $userOptions,
            'schemaOptions' => $schemaOptions,
            'entryQueries' => $entryQueries,
            'entryMutations' => $entryMutations,
            'assetQueries' => $assetQueries,
            'assetMutations' => $assetMutations,
        ]);
    }
}

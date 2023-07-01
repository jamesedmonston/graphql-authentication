<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\Asset;
use craft\elements\db\ElementQuery;
use craft\elements\db\MatrixBlockQuery;
use craft\elements\Entry;
use craft\elements\MatrixBlock;
use craft\elements\User;
use craft\events\ExecuteGqlQueryEvent;
use craft\events\ModelEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\gql\arguments\elements\Asset as AssetArguments;
use craft\gql\arguments\elements\Entry as EntryArguments;
use craft\gql\arguments\elements\GlobalSet as GlobalSetArguments;
use craft\gql\interfaces\elements\Asset as AssetInterface;
use craft\gql\interfaces\elements\Entry as EntryInterface;
use craft\gql\interfaces\elements\GlobalSet as GlobalSetInterface;
use craft\helpers\StringHelper;
use craft\models\GqlToken;
use craft\services\Assets;
use craft\services\Entries;
use craft\services\Gql;
use craft\services\Sections;
use craft\services\Volumes;
use GraphQL\Error\Error;
use GraphQL\Language\AST\FieldNode;
use GraphQL\Language\AST\OperationDefinitionNode;
use GraphQL\Language\Parser;
use GraphQL\Type\Definition\Type;
use InvalidArgumentException;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use jamesedmonston\graphqlauthentication\resolvers\Asset as AssetResolver;
use jamesedmonston\graphqlauthentication\resolvers\Entry as EntryResolver;
use jamesedmonston\graphqlauthentication\resolvers\GlobalSet as GlobalSetResolver;
use yii\base\Event;

class RestrictionService extends Component
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
            Gql::EVENT_BEFORE_EXECUTE_GQL_QUERY,
            [$this, 'restrictForbiddenFields']
        );

        Event::on(
            Entry::class,
            Entry::EVENT_BEFORE_SAVE,
            function (ModelEvent $event) {
                $this->restrictMutationFields($event);
                $this->ensureEntryMutationAllowed($event);
            }
        );

        Event::on(
            Entry::class,
            Entry::EVENT_BEFORE_DELETE,
            [$this, 'ensureEntryMutationAllowed']
        );

        Event::on(
            Asset::class,
            Asset::EVENT_BEFORE_SAVE,
            function (ModelEvent $event) {
                $this->restrictMutationFields($event);
                $this->ensureAssetMutationAllowed($event);
            }
        );

        Event::on(
            Asset::class,
            Asset::EVENT_BEFORE_DELETE,
            [$this, 'ensureAssetMutationAllowed']
        );
    }

    /**
     * Overwrites default Craft resolvers with plugin's restriction-enabled ones from /resolvers
     *
     * @param RegisterGqlQueriesEvent $event
     */
    public function registerGqlQueries(RegisterGqlQueriesEvent $event)
    {
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

        $event->queries['globalSets'] = [
            'description' => 'This query is used to query for global sets.',
            'type' => Type::listOf(GlobalSetInterface::getType()),
            'args' => GlobalSetArguments::getArguments(),
            'resolve' => GlobalSetResolver::class . '::resolve',
        ];

        $event->queries['globalSet'] = [
            'description' => 'This query is used to query for a single global set.',
            'type' => GlobalSetInterface::getType(),
            'args' => GlobalSetArguments::getArguments(),
            'resolve' => GlobalSetResolver::class . '::resolveOne',
        ];
    }

    /**
     * Ensures plugin should be adding user restrictions
     *
     * @return bool
     */
    public function shouldRestrictRequests(): bool
    {
        if (Craft::$app->getRequest()->isConsoleRequest) {
            return false;
        }

        return (bool) GraphqlAuthentication::$tokenService->getHeaderToken();
    }

    /**
     * Ensures plugin should be adding schema restrictions
     *
     * @return bool
     */
    public function shouldRestrictFields(): bool
    {
        if (Craft::$app->getRequest()->isConsoleRequest || Craft::$app->getRequest()->isCpRequest) {
            return false;
        }

        return true;
    }

    /**
     * Ensures the correct schema is returned
     *
     * @return craft\models\GqlSchema
     */
    public function getSchema(): craft\models\GqlSchema
    {
        if ((bool) GraphqlAuthentication::$tokenService->getHeaderToken()) {
            return GraphqlAuthentication::$tokenService->getSchemaFromToken();
        }

        /** @var Gql */
        $gqlService = Craft::$app->getGql();
        $schema = $gqlService->getPublicSchema();

        $requestHeaders = Craft::$app->getRequest()->getHeaders();
        $authHeaders = $requestHeaders->get('authorization', [], false);

        foreach ($authHeaders as $authHeader) {
            $authValues = array_map('trim', explode(',', $authHeader));

            foreach ($authValues as $authValue) {
                if (preg_match('/^Bearer\s+(.+)$/i', $authValue, $matches)) {
                    try {
                        /** @var GqlToken */
                        $token = $gqlService->getTokenByAccessToken($matches[1]);
                        $schema = $token->getSchema();
                    } catch (InvalidArgumentException) {
                    }

                    break 2;
                }
            }
        }

        return $schema;
    }


    /**
     * Restricts private fields from being accessed, based on the schema grabbed from the auth token
     *
     * @param ExecuteGqlQueryEvent $event
     */
    public function restrictForbiddenFields(ExecuteGqlQueryEvent $event)
    {
        if (!$this->shouldRestrictFields()) {
            return;
        }

        $settings = GraphqlAuthentication::$settings;
        $fieldRestrictions = $settings->fieldRestrictions ?? [];

        if (!count($fieldRestrictions)) {
            return;
        }

        /** @var OperationDefinitionNode[] $definitions */
        /** @phpstan-ignore-next-line */
        $definitions = Parser::parse($event->query)->definitions ?? [];

        if (!count($definitions)) {
            return;
        }

        $queries = [];
        $introspectionQueries = [];

        foreach ($definitions as $definition) {
            /** @phpstan-ignore-next-line */
            foreach ($definition->selectionSet->selections ?? [] as $selectionSet) {
                /** @var FieldNode $selectionSet */
                $queries[] = $selectionSet;

                /** @phpstan-ignore-next-line */
                if (StringHelper::containsAny($selectionSet->name->value ?? '', ['__schema', '__type'])) {
                    $introspectionQueries[] = $selectionSet;
                }
            }
        }

        if (count($introspectionQueries) === count($queries)) {
            return;
        }

        $schema = $this->getSchema();
        $schemaCode = $schema->isPublic ? $schema->id : $schema->name;

        $fieldPermissions = $fieldRestrictions['schema-' . $schemaCode] ?? [];

        if (!count($fieldPermissions)) {
            return;
        }

        $errorService = GraphqlAuthentication::$errorService;

        $queryFields = array_keys(array_filter($fieldPermissions, function ($permission) {
            return $permission === 'query';
        }));

        $privateFields = array_keys(array_filter($fieldPermissions, function ($permission) {
            return $permission === 'private';
        }));

        foreach ($definitions as $definition) {
            /** @phpstan-ignore-next-line */
            if (!isset($definition->operation)) {
                continue;
            }

            if ($definition->operation === 'query') {
                $forbiddenArguments = $privateFields;
            } else {
                $forbiddenArguments = array_merge($queryFields, $privateFields);
            }

            /** @phpstan-ignore-next-line */
            foreach ($definition->selectionSet->selections ?? [] as $selectionSet) {
                // loop through arguments
                foreach ($selectionSet->arguments ?? [] as $argument) {
                    if (in_array($argument->name->value ?? '', $forbiddenArguments)) {
                        $errorService->throw($settings->forbiddenField, true);
                    }
                }

                // loop through field selections
                $this->_ensureValidFields($selectionSet, $privateFields);
            }
        }
    }

    /**
     * Loops through mutation fields and checks them against validators
     *
     * @param ModelEvent $event
     * @throws Error
     */
    public function restrictMutationFields(ModelEvent $event)
    {
        if (!$this->shouldRestrictFields()) {
            return;
        }

        /** @var Entry|Asset $element */
        $element = $event->sender;
        $siteId = $element->site->id;

        foreach ($element->getFieldValues() as $fieldValue) {
            if (!$fieldValue instanceof ElementQuery && !$fieldValue instanceof MatrixBlockQuery) {
                continue;
            }

            switch ($fieldValue->elementType) {
                case Entry::class:
                    foreach ($fieldValue->all() as $entry) {
                        $this->_ensureValidEntry($entry->id, $siteId);
                    }
                    break;

                case Asset::class:
                    foreach ($fieldValue->all() as $asset) {
                        $this->_ensureValidAsset($asset->id);
                    }
                    break;

                case MatrixBlock::class:
                    foreach ($fieldValue->all() as $block) {
                        foreach ($block->getFieldValues() as $blockFieldValue) {
                            if (!$blockFieldValue instanceof ElementQuery) {
                                continue;
                            }

                            switch ($blockFieldValue->elementType) {
                                case Entry::class:
                                    foreach ($blockFieldValue->all() as $blockFieldEntry) {
                                        $this->_ensureValidEntry($blockFieldEntry->id, $siteId);
                                    }
                                    break;

                                case Asset::class:
                                    foreach ($blockFieldValue->all() as $blockFieldAsset) {
                                        $this->_ensureValidAsset($blockFieldAsset->id);
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

    /**
     * Ensures user isn't trying to mutate a private entry
     *
     * @param ModelEvent $event
     * @return bool
     * @throws Error
     */
    public function ensureEntryMutationAllowed(ModelEvent $event): bool
    {
        if (!$this->shouldRestrictRequests()) {
            return true;
        }

        /** @var Entry $entry */
        $entry = $event->sender;
        $user = GraphqlAuthentication::$tokenService->getUserFromToken();

        if ($user && $event->isNew && !$entry->authorId) {
            $entry->authorId = $user->id;
        }

        $authorOnlySections = isset($user) && $user ? $this->getAuthorOnlySections($user, 'mutation') : [];

        /** @var Sections */
        $sectionsService = Craft::$app->getSections();
        $entrySection = $sectionsService->getSectionById($entry->sectionId)->handle;

        if (!in_array($entrySection, $authorOnlySections)) {
            return true;
        }

        if (!$user || $entry->authorId != $user->id) {
            GraphqlAuthentication::$errorService->throw(GraphqlAuthentication::$settings->forbiddenMutation);
        }

        return true;
    }

    /**
     * Ensures user isn't trying to mutate a private asset
     *
     * @param ModelEvent $event
     * @return bool
     * @throws Error
     */
    public function ensureAssetMutationAllowed(ModelEvent $event): bool
    {
        if (!$this->shouldRestrictRequests()) {
            return true;
        }

        /** @var Asset $asset */
        $asset = $event->sender;
        $user = GraphqlAuthentication::$tokenService->getUserFromToken();

        if ($user && $event->isNew && !$asset->uploaderId) {
            $asset->uploaderId = $user->id;
            return true;
        }

        $authorOnlyVolumes = isset($user) && $user ? $this->getAuthorOnlyVolumes($user, 'mutation') : [];

        /** @var Volumes */
        $volumesService = Craft::$app->getVolumes();
        $assetVolume = $volumesService->getVolumeById($asset->volumeId)->handle;

        if (!in_array($assetVolume, $authorOnlyVolumes)) {
            return true;
        }

        if (!$user || $asset->uploaderId != $user->id) {
            GraphqlAuthentication::$errorService->throw(GraphqlAuthentication::$settings->forbiddenMutation);
        }

        return true;
    }

    /**
     * Gets author-only sections from plugin settings
     *
     * @param User $user
     * @param string $type
     * @return array
     */
    public function getAuthorOnlySections(User $user, $type): array
    {
        $settings = GraphqlAuthentication::$settings;

        if ($type === 'query') {
            $authorOnlySections = $settings->entryQueries ?? [];
        } else {
            $authorOnlySections = $settings->entryMutations ?? [];
        }

        if ($settings->permissionType === 'multiple') {
            $userGroup = $user->getGroups()[0] ?? null;

            if ($userGroup) {
                $permissions = $settings->granularSchemas["group-{$userGroup->id}"];

                if ($type === 'query') {
                    $authorOnlySections = $permissions['entryQueries'] ?? [];
                } else {
                    $authorOnlySections = $permissions['entryMutations'] ?? [];
                }
            }
        }

        $authorOnlySections = array_keys(array_filter($authorOnlySections, function ($section) {
            return (bool) $section;
        }));

        return $authorOnlySections;
    }

    /**
     * Gets author-only volumes from plugin settings
     *
     * @param User $user
     * @param string $type
     * @return array
     */
    public function getAuthorOnlyVolumes($user, $type): array
    {
        $settings = GraphqlAuthentication::$settings;
        $authorOnlyVolumes = [];

        if ($type === 'query') {
            $authorOnlyVolumes = $settings->assetQueries ?? [];
        } else {
            $authorOnlyVolumes = $settings->assetMutations ?? [];
        }

        if ($settings->permissionType === 'multiple') {
            $userGroup = $user->getGroups()[0] ?? null;

            if ($userGroup) {
                $permissions = $settings->granularSchemas["group-{$userGroup->id}"];

                if ($type === 'query') {
                    $authorOnlyVolumes = $permissions['assetQueries'] ?? [];
                } else {
                    $authorOnlyVolumes = $permissions['assetMutations'] ?? [];
                }
            }
        }

        $authorOnlyVolumes = array_keys(array_filter($authorOnlyVolumes, function ($section) {
            return (bool) $section;
        }));

        return $authorOnlyVolumes;
    }

    // Protected Methods
    // =========================================================================

    /**
     * Recurses through query and mutation field selections, ensuring they're queryable
     *
     * @param $selectionSet
     * @param array $fields
     * @throws Error
     */
    private function _ensureValidFields($selectionSet, array $fields)
    {
        $errorService = GraphqlAuthentication::$errorService;
        $settings = GraphqlAuthentication::$settings;

        /** @var FieldNode */
        foreach ($selectionSet->selectionSet->selections ?? [] as $field) {
            /** @phpstan-ignore-next-line */
            if (in_array($field->name->value ?? '', $fields)) {
                $errorService->throw($settings->forbiddenField, true);
            }

            if (count($field->selectionSet->selections ?? [])) {
                $this->_ensureValidFields($field, $fields);
            }
        }
    }

    /**
     * Ensures entry being accessed isn't private
     *
     * @param int $id
     * @param int $siteId
     * @return bool
     * @throws Error
     */
    protected function _ensureValidEntry(int $id, int $siteId): bool
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        /** @var Entries */
        $entriesService = Craft::$app->getEntries();
        $entry = $entriesService->getEntryById($id, $siteId);

        if (!$entry) {
            $errorService->throw($settings->entryNotFound);
        }

        if (!$entry->authorId) {
            return true;
        }

        $tokenService = GraphqlAuthentication::$tokenService;

        if ($tokenService->getHeaderToken()) {
            $user = $tokenService->getUserFromToken();

            if ($user && $entry->authorId == $user->id) {
                return true;
            }
        }

        $scope = $this->getSchema()->scope;

        if (!in_array("sections.{$entry->section->uid}:read", $scope)) {
            $errorService->throw($settings->forbiddenMutation);
        }

        $authorOnlySections = isset($user) && $user ? $this->getAuthorOnlySections($user, 'mutation') : [];

        /** @var Sections */
        $sectionsService = Craft::$app->getSections();
        $entrySection = $sectionsService->getSectionById($entry->sectionId)->handle;

        if (in_array($entrySection, $authorOnlySections)) {
            $errorService->throw($settings->forbiddenMutation);
        }

        return true;
    }

    /**
     * Ensures asset being accessed isn't private
     *
     * @param int $id
     * @return bool
     * @throws Error
     */
    protected function _ensureValidAsset(int $id): bool
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        /** @var Assets */
        $assetsService = Craft::$app->getAssets();
        $asset = $assetsService->getAssetById($id);

        if (!$asset) {
            $errorService->throw($settings->assetNotFound);
        }

        if (!$asset->uploaderId) {
            return true;
        }

        $tokenService = GraphqlAuthentication::$tokenService;

        if ($tokenService->getHeaderToken()) {
            $user = $tokenService->getUserFromToken();

            if ((string) $asset->uploaderId === (string) $user->id) {
                return true;
            }
        }

        $scope = $this->getSchema()->scope;

        if (!in_array("volumes.{$asset->volume->uid}:read", $scope)) {
            $errorService->throw($settings->forbiddenMutation);
        }

        $authorOnlyVolumes = isset($user) && $user ? $this->getAuthorOnlyVolumes($user, 'mutation') : [];

        /** @var Volumes */
        $volumesService = Craft::$app->getVolumes();
        $assetVolume = $volumesService->getVolumeById($asset->volumeId)->handle;

        if (in_array($assetVolume, $authorOnlyVolumes)) {
            $errorService->throw($settings->forbiddenMutation);
        }

        return true;
    }
}

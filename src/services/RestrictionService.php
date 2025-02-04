<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\base\ElementInterface;
use craft\base\NestedElementInterface;
use craft\elements\Asset;
use craft\elements\db\ElementQuery;
use craft\elements\Entry;
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
use craft\helpers\Gql as GqlHelper;
use craft\helpers\StringHelper;
use craft\models\GqlSchema;
use craft\services\Entries;
use craft\services\Gql;
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
            function(ModelEvent $event) {
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
            function(ModelEvent $event) {
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
        if (!GraphqlAuthentication::$tokenService->getHeaderToken()) {
            return;
        }

        $resolvers = [
            'entries' => EntryResolver::class . '::resolve',
            'entry' => EntryResolver::class . '::resolveOne',
            'entryCount' => EntryResolver::class . '::resolveCount',
            'assets' => AssetResolver::class . '::resolve',
            'asset' => AssetResolver::class . '::resolveOne',
            'assetCount' => AssetResolver::class . '::resolveCount',
            'globalSets' => GlobalSetResolver::class . '::resolve',
            'globalSet' => GlobalSetResolver::class . '::resolveOne',
        ];

        foreach (Craft::$app->getEntries()->getAllSections() as $section) {
            // "Entries" was added in Craft 5.6.5
            $resolvers[$section->handle] = EntryResolver::class . '::resolve';
            $resolvers["{$section->handle}Entries"] = EntryResolver::class . '::resolve';
        }

        foreach ($resolvers as $name => $resolver) {
            if (isset($event->queries[$name])) {
                $event->queries[$name]['resolver'] = $resolver;
            }
        }
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
     * @return GqlSchema
     */
    public function getSchema(): GqlSchema
    {
        if (GraphqlAuthentication::$tokenService->getHeaderToken()) {
            return GraphqlAuthentication::$tokenService->getSchemaFromToken();
        }

        $gqlService = Craft::$app->getGql();
        $schema = $gqlService->getPublicSchema();

        $requestHeaders = Craft::$app->getRequest()->getHeaders();
        $authHeaders = $requestHeaders->get('authorization', [], false);

        foreach ($authHeaders as $authHeader) {
            $authValues = array_map('trim', explode(',', $authHeader));

            foreach ($authValues as $authValue) {
                if (preg_match('/^Bearer\s+(.+)$/i', $authValue, $matches)) {
                    try {
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

        $queryFields = array_keys(array_filter($fieldPermissions, function($permission) {
            return $permission === 'query';
        }));

        $privateFields = array_keys(array_filter($fieldPermissions, function($permission) {
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
        $this->restrictMutationFieldsForElement($element);
    }

    private function restrictMutationFieldsForElement(ElementInterface $element): void
    {
        foreach ($element->getFieldValues() as $fieldValue) {
            if (!$fieldValue instanceof ElementQuery) {
                continue;
            }

            foreach ($fieldValue->all() as $e) {
                if ($e instanceof NestedElementInterface && $e->getOwnerId()) {
                    $this->restrictMutationFieldsForElement($e);
                } elseif ($e instanceof Entry) {
                    $this->_ensureValidEntry($e->id, $element->siteId);
                } elseif ($e instanceof Asset) {
                    $this->_ensureValidAsset($e->id);
                }
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

        $authorOnlySections = $user ? $this->getAuthorOnlySections($user, 'mutation') : [];

        $entriesService = Craft::$app->getEntries();
        $entrySection = $entriesService->getSectionById($entry->sectionId)->handle;

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

        $authorOnlyVolumes = $user ? $this->getAuthorOnlyVolumes($user, 'mutation') : [];

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

        $authorOnlySections = array_keys(array_filter($authorOnlySections, function($section) {
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

        $authorOnlyVolumes = array_keys(array_filter($authorOnlyVolumes, function($section) {
            return (bool) $section;
        }));

        return $authorOnlyVolumes;
    }

    // Protected Methods
    // =========================================================================

    /**
     * Recurses through query and mutation field selections, ensuring they're queryable
     *
     * @param FieldNode $selectionSet
     * @param array $fields
     * @throws Error
     */
    private function _ensureValidFields($selectionSet, array $fields)
    {
        $errorService = GraphqlAuthentication::$errorService;
        $settings = GraphqlAuthentication::$settings;

        foreach ($selectionSet->selectionSet->selections ?? [] as $field) {
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

        $entriesService = Craft::$app->getEntries();
        $entry = $entriesService->getEntryById($id, $siteId);

        if (!$entry) {
            $errorService->throw($settings->entryNotFound);
        }

        if (!$entry->authorId) {
            return true;
        }

        $tokenService = GraphqlAuthentication::$tokenService;
        $user = null;

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

        $authorOnlySections = $user ? $this->getAuthorOnlySections($user, 'mutation') : [];

        $entrySection = $entriesService->getSectionById($entry->sectionId)->handle;

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

        $assetsService = Craft::$app->getAssets();
        $asset = $assetsService->getAssetById($id);

        if (!$asset) {
            $errorService->throw($settings->assetNotFound);
        }

        if (!$asset->uploaderId) {
            return true;
        }

        $tokenService = GraphqlAuthentication::$tokenService;
        $user = null;

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

        $authorOnlyVolumes = $user ? $this->getAuthorOnlyVolumes($user, 'mutation') : [];

        $volumesService = Craft::$app->getVolumes();
        $assetVolume = $volumesService->getVolumeById($asset->volumeId)->handle;

        if (in_array($assetVolume, $authorOnlyVolumes)) {
            $errorService->throw($settings->forbiddenMutation);
        }

        return true;
    }
}

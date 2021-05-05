<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\Asset;
use craft\elements\Entry;
use craft\events\ModelEvent;
use craft\events\RegisterGqlQueriesEvent;
use craft\gql\arguments\elements\Asset as AssetArguments;
use craft\gql\arguments\elements\Entry as EntryArguments;
use craft\gql\interfaces\elements\Asset as AssetInterface;
use craft\gql\interfaces\elements\Entry as EntryInterface;
use craft\services\Assets;
use craft\services\Elements;
use craft\services\Gql;
use craft\services\Sections;
use craft\services\Volumes;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use jamesedmonston\graphqlauthentication\resolvers\Asset as AssetResolver;
use jamesedmonston\graphqlauthentication\resolvers\Entry as EntryResolver;
use yii\base\Event;

class RestrictionService extends Component
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
    }

    /**
     * Loops through mutation fields and checks them against validators
     *
     * @param ModelEvent $event
     * @throws Error
     */
    public function restrictMutationFields(ModelEvent $event)
    {
        if (!$this->shouldRestrictRequests()) {
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
                    foreach ($field->all() as $matrixBlock) {
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

    /**
     * Ensures user isn't trying to mutate a private entry
     *
     * @param ModelEvent $event
     * @throws Error
     */
    public function ensureEntryMutationAllowed(ModelEvent $event)
    {
        if (!$this->shouldRestrictRequests()) {
            return;
        }

        $this->_ensureValidEntry($event->sender->id);
    }

    /**
     * Ensures user isn't trying to mutate a private asset
     *
     * @param ModelEvent $event
     * @return bool
     */
    public function ensureAssetMutationAllowed(ModelEvent $event)
    {
        if (!$this->shouldRestrictRequests()) {
            return;
        }

        $this->_ensureValidAsset($event->sender->id);
    }

    /**
     * Ensures plugin should be adding user/schema restrictions
     *
     * @return bool
     */
    public function shouldRestrictRequests(): bool
    {
        return (bool) GraphqlAuthentication::$tokenService->getHeaderToken();
    }

    // Protected Methods
    // =========================================================================

    /**
     * Ensures entry being accessed isn't private
     *
     * @param int $id
     * @return bool
     * @throws Error
     */
    protected function _ensureValidEntry(int $id): bool
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        /** @var Elements */
        $elementsService = Craft::$app->getElements();
        $entry = $elementsService->getElementById($id);

        if (!$entry) {
            $errorService->throw($settings->entryNotFound, 'INVALID');
        }

        if (!$entry->authorId) {
            return true;
        }

        $tokenService = GraphqlAuthentication::$tokenService;
        $user = $tokenService->getUserFromToken();

        if ((string) $entry->authorId === (string) $user->id) {
            return true;
        }

        $scope = $tokenService->getSchemaFromToken()->getScope();

        if (!in_array("sections.{$entry->section->uid}:read", $scope)) {
            $errorService->throw($settings->forbiddenMutation, 'FORBIDDEN');
        }

        $authorOnlySections = $settings->entryMutations ?? [];

        if ($settings->permissionType === 'multiple') {
            $userGroup = $user->getGroups()[0] ?? null;

            if ($userGroup) {
                $authorOnlySections = $settings->granularSchemas["group-{$userGroup->id}"]['entryMutations'] ?? [];
            }
        }

        /** @var Sections */
        $sectionsService = Craft::$app->getSections();
        $entrySection = $sectionsService->getSectionById($entry->sectionId)->handle;

        if (in_array($entrySection, array_keys($authorOnlySections))) {
            $errorService->throw($settings->forbiddenMutation, 'FORBIDDEN');
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
            $errorService->throw($settings->assetNotFound, 'INVALID');
        }

        if (!$asset->uploaderId) {
            return true;
        }

        $tokenService = GraphqlAuthentication::$tokenService;
        $user = $tokenService->getUserFromToken();

        if ((string) $asset->uploaderId === (string) $user->id) {
            return true;
        }

        $scope = $tokenService->getSchemaFromToken()->getScope();

        if (!in_array("volumes.{$asset->volume->uid}:read", $scope)) {
            $errorService->throw($settings->forbiddenMutation, 'FORBIDDEN');
        }

        $authorOnlyVolumes = $settings->assetMutations ?? [];

        if ($settings->permissionType === 'multiple') {
            $userGroup = $user->getGroups()[0] ?? null;

            if ($userGroup) {
                $authorOnlyVolumes = $settings->granularSchemas["group-{$userGroup->id}"]['assetMutations'] ?? [];
            }
        }

        /** @var Volumes */
        $volumesService = Craft::$app->getVolumes();
        $assetVolume = $volumesService->getVolumeById($asset->volumeId)->handle;

        if (in_array($assetVolume, array_keys($authorOnlyVolumes))) {
            $errorService->throw($settings->forbiddenMutation, 'FORBIDDEN');
        }

        return true;
    }
}

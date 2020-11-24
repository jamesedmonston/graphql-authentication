<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\Asset;
use craft\elements\Entry;
use craft\events\ModelEvent;
use craft\gql\arguments\elements\Asset as AssetArguments;
use craft\gql\arguments\elements\Entry as EntryArguments;
use craft\gql\interfaces\elements\Asset as AssetInterface;
use craft\gql\interfaces\elements\Entry as EntryInterface;
use craft\services\Gql;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use jamesedmonston\graphqlauthentication\resolvers\Asset as AssetResolver;
use jamesedmonston\graphqlauthentication\resolvers\Entry as EntryResolver;
use yii\base\Event;

class RestrictionService extends Component
{
    public static $FORBIDDEN_MUTATION = "User doesn't have permission to perform this mutation";
    public static $ENTRY_NOT_FOUND = "We couldn't find any matching entries";
    public static $ASSET_NOT_FOUND = "We couldn't find any matching assets";

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
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

    public function registerGqlQueries(Event $event)
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

    // Protected Methods
    // =========================================================================

    protected function _shouldRestrictRequests(): bool
    {
        $request = Craft::$app->getRequest();

        if ($request->isConsoleRequest || GraphqlAuthentication::$plugin->isGraphiqlRequest()) {
            return false;
        }

        return (bool) $request->getBodyParam('query');
    }

    public function restrictMutationFields(ModelEvent $event)
    {
        if (!$this->_shouldRestrictRequests()) {
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
        if (!$this->_shouldRestrictRequests()) {
            return;
        }

        $user = GraphqlAuthentication::$plugin->getInstance()->user->getUserFromToken();

        if ($event->isNew) {
            $event->sender->authorId = $user->id;
            return;
        }

        $authorOnlySections = GraphqlAuthentication::$plugin->getSettings()->entryMutations ?? [];
        $entrySection = Craft::$app->getSections()->getSectionById($event->sender->sectionId)->handle;

        if (!in_array($entrySection, array_keys($authorOnlySections))) {
            return;
        }

        foreach ($authorOnlySections as $section => $value) {
            if (!(bool) $value || $section !== $entrySection) {
                continue;
            }

            if ((string) $event->sender->authorId !== (string) $user->id) {
                throw new Error(self::$FORBIDDEN_MUTATION);
            }
        }
    }

    public function ensureAssetMutationAllowed(ModelEvent $event)
    {
        if (!$this->_shouldRestrictRequests()) {
            return;
        }

        $user = GraphqlAuthentication::$plugin->getInstance()->user->getUserFromToken();

        if ($event->isNew) {
            $event->sender->uploaderId = $user->id;
            return;
        }

        $authorOnlyVolumes = GraphqlAuthentication::$plugin->getSettings()->assetMutations ?? [];
        $assetVolume = Craft::$app->getVolumes()->getVolumeById($event->sender->volumeId)->handle;

        if (!in_array($assetVolume, array_keys($authorOnlyVolumes))) {
            return;
        }

        foreach ($authorOnlyVolumes as $volume => $value) {
            if (!(bool) $value || $volume !== $assetVolume) {
                continue;
            }

            if ((string) $event->sender->uploaderId !== (string) $user->id) {
                throw new Error(self::$FORBIDDEN_MUTATION);
            }
        }
    }

    protected function _ensureValidEntry(int $id)
    {
        $entry = Craft::$app->getElements()->getElementById($id);

        if (!$entry) {
            throw new Error(self::$ENTRY_NOT_FOUND);
        }

        if (!$entry->authorId) {
            return;
        }

        $user = GraphqlAuthentication::$plugin->getInstance()->user->getUserFromToken();

        if ((string) $entry->authorId === (string) $user->id) {
            return;
        }

        $scope = GraphqlAuthentication::$plugin->getInstance()->token->getHeaderToken()->getScope();

        if (!in_array("sections.{$entry->section->uid}:read", $scope)) {
            throw new Error(self::$FORBIDDEN_MUTATION);
        }

        $sections = Craft::$app->getSections();
        $authorOnlySections = GraphqlAuthentication::$plugin->getSettings()->entryQueries ?? [];

        foreach ($authorOnlySections as $section => $value) {
            if (!(bool) $value) {
                continue;
            }

            if ($entry->sectionId !== $sections->getSectionByHandle($section)->id) {
                continue;
            }

            throw new Error(self::$FORBIDDEN_MUTATION);
        }
    }

    protected function _ensureValidAsset(int $id)
    {
        $asset = Craft::$app->getAssets()->getAssetById($id);

        if (!$asset) {
            throw new Error(self::$ASSET_NOT_FOUND);
        }

        if (!$asset->uploaderId) {
            return;
        }

        $user = GraphqlAuthentication::$plugin->getInstance()->user->getUserFromToken();

        if ((string) $asset->uploaderId === (string) $user->id) {
            return;
        }

        $scope = GraphqlAuthentication::$plugin->getInstance()->token->getHeaderToken()->getScope();

        if (!in_array("volumes.{$asset->volume->uid}:read", $scope)) {
            throw new Error(self::$FORBIDDEN_MUTATION);
        }

        $volumes = Craft::$app->getVolumes()->getAllVolumes();
        $authorOnlyVolumes = GraphqlAuthentication::$plugin->getSettings()->assetQueries ?? [];

        foreach ($authorOnlyVolumes as $volume => $value) {
            if (!(bool) $value) {
                continue;
            }

            if ($asset->volumeId !== $volumes->getVolumeByHandle($volume)->id) {
                continue;
            }

            throw new Error(self::$FORBIDDEN_MUTATION);
        }
    }
}

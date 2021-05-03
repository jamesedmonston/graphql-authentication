<?php
/**
 * Duplicated from /vendor/craftcms/cms/src/gql/resolvers/elements/Entry.php
 */

namespace jamesedmonston\graphqlauthentication\resolvers;

use Craft;
use craft\db\Table;
use craft\elements\Entry as EntryElement;
use craft\gql\base\ElementResolver;
use craft\helpers\Db;
use craft\helpers\Gql as GqlHelper;
use craft\services\Sections;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

/**
 * Class Entry
 *
 * @author Pixel & Tonic, Inc. <support@pixelandtonic.com>
 * @since 3.3.0
 */
class Entry extends ElementResolver
{
    /**
     * @inheritdoc
     */
    public static function prepareQuery($source, array $arguments, $fieldName = null)
    {
        // If this is the beginning of a resolver chain, start fresh
        if ($source === null) {
            $query = EntryElement::find();
            // If not, get the prepared element query
        } else {
            $query = $source->$fieldName;
        }

        // If it's preloaded, it's preloaded.
        if (is_array($query)) {
            return $query;
        }

        if (GraphqlAuthentication::$restrictionService->shouldRestrictRequests()) {
            $user = GraphqlAuthentication::$tokenService->getUserFromToken();

            if (isset($arguments['section']) || isset($arguments['sectionId'])) {
                $settings = GraphqlAuthentication::$settings;
                $authorOnlySections = $settings->entryQueries ?? [];
                $siteId = $settings->siteId ?? null;

                if ($settings->permissionType === 'multiple') {
                    $userGroup = $user->getGroups()[0] ?? null;

                    if ($userGroup) {
                        $authorOnlySections = $settings->granularSchemas["group-{$userGroup->id}"]['entryQueries'] ?? [];
                        $siteId = $settings->granularSchemas["group-{$userGroup->id}"]['siteId'] ?? null;
                    }
                }

                if ($siteId) {
                    $arguments['siteId'] = $siteId;
                }

                /** @var Sections */
                $sectionsService = Craft::$app->getSections();

                foreach ($authorOnlySections as $section => $value) {
                    if (!(bool) $value) {
                        continue;
                    }

                    if (isset($arguments['section']) && trim($arguments['section'][0]) !== $section) {
                        continue;
                    }

                    if (isset($arguments['sectionId']) && trim((string) $arguments['sectionId'][0]) !== $sectionsService->getSectionByHandle($section)->id) {
                        continue;
                    }

                    $arguments['authorId'] = $user->id;
                }
            } else {
                $arguments['authorId'] = $user->id;
            }
        }

        foreach ($arguments as $key => $value) {
            $query->$key($value);
        }

        $pairs = GqlHelper::extractAllowedEntitiesFromSchema('read');

        if (!GqlHelper::canQueryEntries()) {
            return [];
        }

        $query->andWhere(['in', 'entries.sectionId', array_values(Db::idsByUids(Table::SECTIONS, $pairs['sections']))]);
        $query->andWhere(['in', 'entries.typeId', array_values(Db::idsByUids(Table::ENTRYTYPES, $pairs['entrytypes']))]);

        return $query;
    }
}

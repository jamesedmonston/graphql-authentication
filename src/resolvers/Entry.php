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
    public static function prepareQuery(mixed $source, array $arguments, ?string $fieldName = null): mixed
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

        $restrictionService = GraphqlAuthentication::$restrictionService;

        if ($restrictionService->shouldRestrictRequests()) {
            $user = GraphqlAuthentication::$tokenService->getUserFromToken();

            if (isset($arguments['section']) || isset($arguments['sectionId'])) {
                $authorOnlySections = $user ? $restrictionService->getAuthorOnlySections($user, 'query') : [];

                $entriesService = Craft::$app->getEntries();

                foreach ($authorOnlySections as $section) {
                    if (isset($arguments['section']) && trim($arguments['section'][0]) !== $section) {
                        continue;
                    }

                    if (isset($arguments['sectionId']) && trim((string) $arguments['sectionId'][0]) !== $entriesService->getSectionByHandle($section)->id) {
                        continue;
                    }

                    $arguments['authorId'] = $user->id;
                }

                $settings = GraphqlAuthentication::$settings;
                $siteId = null;

                if ($settings->permissionType === 'single') {
                    $siteId = $settings->siteId ?? null;
                } else {
                    $userGroup = $user ? ($user->getGroups()[0]->id ?? null) : null;

                    if ($userGroup) {
                        $siteId = $settings->granularSchemas["group-${userGroup}"]['siteId'] ?? null;
                    }
                }

                if ($siteId) {
                    $arguments['siteId'] = $siteId;
                }
            } elseif ($user) {
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

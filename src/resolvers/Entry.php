<?php
/**
 * Duplicated from /vendor/craftcms/cms/src/gql/resolvers/elements/Entry.php
 */

namespace jamesedmonston\graphqlauthentication\resolvers;

use Craft;
use craft\elements\db\ElementQuery;
use craft\elements\ElementCollection;
use craft\elements\Entry as EntryElement;
use craft\gql\base\ElementResolver;
use craft\helpers\Gql as GqlHelper;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\UnknownMethodException;

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
            $pairs = GqlHelper::extractAllowedEntitiesFromSchema('read');
            $condition = [];

            if (isset($pairs['sections'])) {
                $entriesService = Craft::$app->getEntries();
                $sectionIds = array_filter(array_map(
                    fn(string $uid) => $entriesService->getSectionByUid($uid)?->id,
                    $pairs['sections'],
                ));
                if (!empty($sectionIds)) {
                    $condition[] = ['in', 'entries.sectionId', $sectionIds];
                }
            }

            if (isset($pairs['nestedentryfields'])) {
                $fieldsService = Craft::$app->getFields();
                $types = array_flip($fieldsService->getNestedEntryFieldTypes());
                $fieldIds = array_filter(array_map(function(string $uid) use ($fieldsService, $types) {
                    $field = $fieldsService->getFieldByUid($uid);
                    return $field && isset($types[$field::class]) ? $field->id : null;
                }, $pairs['nestedentryfields']));
                if (!empty($fieldIds)) {
                    $condition[] = ['in', 'entries.fieldId', $fieldIds];
                }
            }

            if (empty($condition)) {
                return ElementCollection::empty();
            }

            $query->andWhere(['or', ...$condition]);
        // If not, get the prepared element query
        } else {
            $query = $source->$fieldName;
        }

        // If it's preloaded, it's preloaded.
        if (!$query instanceof ElementQuery) {
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
                        $siteId = $settings->granularSchemas["group-$userGroup"]['siteId'] ?? null;
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
            try {
                $query->$key($value);
            } catch (UnknownMethodException $e) {
                if ($value !== null) {
                    throw $e;
                }
            }
        }

        return $query;
    }
}

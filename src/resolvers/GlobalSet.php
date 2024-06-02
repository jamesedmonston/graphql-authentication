<?php
/**
 * Duplicated from /vendor/craftcms/cms/src/gql/resolvers/elements/GlobalSet.php
 */

namespace jamesedmonston\graphqlauthentication\resolvers;

use craft\elements\ElementCollection;
use craft\elements\GlobalSet as GlobalSetElement;
use craft\gql\base\ElementResolver;
use craft\helpers\Gql as GqlHelper;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\UnknownMethodException;

/**
 * Class GlobalSet
 *
 * @author Pixel & Tonic, Inc. <support@pixelandtonic.com>
 * @since 3.3.0
 */
class GlobalSet extends ElementResolver
{
    /**
     * @inheritdoc
     */
    public static function prepareQuery(mixed $source, array $arguments, ?string $fieldName = null): mixed
    {
        $query = GlobalSetElement::find();

        if (GraphqlAuthentication::$restrictionService->shouldRestrictRequests()) {
            $settings = GraphqlAuthentication::$settings;
            $siteId = null;

            if ($settings->permissionType === 'single') {
                $siteId = $settings->siteId ?? null;
            } else {
                $user = GraphqlAuthentication::$tokenService->getUserFromToken();
                $userGroup = $user->getGroups()[0]->id ?? null;

                if ($userGroup) {
                    $siteId = $settings->granularSchemas["group-$userGroup"]['siteId'] ?? null;
                }
            }

            if ($siteId) {
                $arguments['siteId'] = $siteId;
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

        $pairs = GqlHelper::extractAllowedEntitiesFromSchema('read');

        if (!GqlHelper::canQueryGlobalSets()) {
            return ElementCollection::empty();
        }

        $query->andWhere(['in', 'globalsets.uid', $pairs['globalsets']]);

        return $query;
    }
}

<?php
/**
 * Duplicated from /vendor/craftcms/cms/src/gql/resolvers/elements/Asset.php
 */

namespace jamesedmonston\graphqlauthentication\resolvers;

use Craft;
use craft\db\Table;
use craft\elements\Asset as AssetElement;
use craft\gql\base\ElementResolver;
use craft\helpers\Db;
use craft\helpers\Gql as GqlHelper;
use craft\helpers\StringHelper;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

/**
 * Class Asset
 *
 * @author Pixel & Tonic, Inc. <support@pixelandtonic.com>
 * @since 3.3.0
 */
class Asset extends ElementResolver
{
    /**
     * @inheritdoc
     */
    public static function prepareQuery($source, array $arguments, $fieldName = null)
    {
        // If this is the beginning of a resolver chain, start fresh
        if ($source === null) {
            $query = AssetElement::find();
            // If not, get the prepared element query
        } else {
            $query = $source->$fieldName;
        }

        // If it's preloaded, it's preloaded.
        if (is_array($query)) {
            return $query;
        }

        if (!GraphqlAuthentication::$plugin->isGraphiqlRequest()) {
            $token = GraphqlAuthentication::$plugin->getInstance()->token->getHeaderToken();

            if (StringHelper::contains($token, 'user-')) {
                $arguments['uploader'] = GraphqlAuthentication::$plugin->getInstance()->token->getUserFromToken()->id;

                if (isset($arguments['volume']) || isset($arguments['volumeId'])) {
                    unset($arguments['uploader']);
                    $authorOnlyVolumes = GraphqlAuthentication::$plugin->getSettings()->assetQueries ?? [];

                    foreach ($authorOnlyVolumes as $volume => $value) {
                        if (!(bool) $value) {
                            continue;
                        }

                        if (isset($arguments['volume']) && trim($arguments['volume'][0]) !== $volume) {
                            continue;
                        }

                        if (isset($arguments['volumeId']) && trim((string) $arguments['volumeId'][0]) !== Craft::$app->getVolumes()->getVolumeByHandle($volume)->id) {
                            continue;
                        }

                        $arguments['uploader'] = GraphqlAuthentication::$plugin->getInstance()->token->getUserFromToken()->id;
                    }
                }
            }
        }

        foreach ($arguments as $key => $value) {
            $query->$key($value);
        }

        $pairs = GqlHelper::extractAllowedEntitiesFromSchema('read');

        if (!GqlHelper::canQueryAssets()) {
            return [];
        }

        $query->andWhere(['in', 'assets.volumeId', array_values(Db::idsByUids(Table::VOLUMES, $pairs['volumes']))]);

        return $query;
    }
}

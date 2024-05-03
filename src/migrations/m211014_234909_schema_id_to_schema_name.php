<?php

namespace jamesedmonston\graphqlauthentication\migrations;

use Craft;
use craft\db\Migration;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Plugins;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

/**
 * m211014_234909_schema_id_to_schema_name migration.
 */
class m211014_234909_schema_id_to_schema_name extends Migration
{
    // Public Methods
    // =========================================================================

    public function safeUp()
    {
        $projectConfig = Craft::$app->projectConfig;

        // Don’t make the same config changes twice
        $schemaVersion = $projectConfig->get('plugins.graphql-authentication.schemaVersion', true);

        if (version_compare($schemaVersion, '1.2.0', '<')) {
            $plugins = Craft::$app->getPlugins();
            $settings = GraphqlAuthentication::$settings;

            if ($settings->schemaId) {
                $schemaName = GqlSchemaRecord::find()->select(['name'])->where(['id' => $settings->schemaId])->scalar();

                $plugins->savePluginSettings(GraphqlAuthentication::$plugin, [
                    'schemaId' => null,
                    'schemaName' => $schemaName,
                ]);
            }

            if (count($settings->granularSchemas ?? [])) {
                $granularSchemas = $settings->granularSchemas;

                foreach ($granularSchemas as &$schema) {
                    if (array_key_exists('schemaId', $schema)) {
                        $schemaName = GqlSchemaRecord::find()->select(['name'])->where(['id' => $schema['schemaId']])->scalar();
                        unset($schema['schemaId']);
                        $schema['schemaName'] = $schemaName;
                    }
                }

                $plugins->savePluginSettings(GraphqlAuthentication::$plugin, ['granularSchemas' => $granularSchemas]);
            }
        }

        return true;
    }

    public function safeDown()
    {
    }
}

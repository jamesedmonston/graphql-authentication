<?php

namespace jamesedmonston\graphqlauthentication\migrations;

use Craft;
use craft\db\Migration;
use craft\records\GqlSchema as GqlSchemaRecord;
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
            $settings = GraphqlAuthentication::$settings;

            if ($settings['schemaId']) {
                $schemaName = GqlSchemaRecord::find()->select(['name'])->where(['id' => $settings->schemaId])->scalar();
                $projectConfig->set('plugins.graphql-authentication.settings.schemaName', $schemaName);
                $projectConfig->remove('plugins.graphql-authentication.settings.schemaId');
            }
        }

        return true;
    }

    public function safeDown()
    {
        $settings = GraphqlAuthentication::$settings;

        if ($settings['schemaName']) {
            $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();
            Craft::$app->getPlugins()->savePluginSettings(GraphqlAuthentication::$plugin, ['schemaId' => $schemaId]);
        }

        return true;
    }
}

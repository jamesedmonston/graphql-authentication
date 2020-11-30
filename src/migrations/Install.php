<?php

namespace jamesedmonston\graphqlauthentication\migrations;

use Craft;
use craft\db\Migration;

class Install extends Migration
{
    // Public Properties
    // =========================================================================

    /**
     * @var string The database driver to use
     */
    public $driver;

    // Public Methods
    // =========================================================================

    /**
     * This method contains the logic to be executed when applying this migration.
     * This method differs from [[up()]] in that the DB logic implemented here will
     * be enclosed within a DB transaction.
     * Child classes may implement this method instead of [[up()]] if the DB logic
     * needs to be within a transaction.
     *
     * @return bool return a false value to indicate the migration fails
     *              and should not proceed further. All other return values mean the migration succeeds.
     */
    public function safeUp()
    {
        $this->driver = Craft::$app->getConfig()->getDb()->driver;

        if ($this->createTables()) {
            $this->createIndexes();
            $this->addForeignKeys();
            // Refresh the db schema caches
            Craft::$app->db->schema->refresh();
            $this->insertDefaultData();
        }

        return true;
    }

    /**
     * This method contains the logic to be executed when removing this migration.
     * This method differs from [[down()]] in that the DB logic implemented here will
     * be enclosed within a DB transaction.
     * Child classes may implement this method instead of [[down()]] if the DB logic
     * needs to be within a transaction.
     *
     * @return bool return a false value to indicate the migration fails
     *              and should not proceed further. All other return values mean the migration succeeds.
     */
    public function safeDown()
    {
        $this->driver = Craft::$app->getConfig()->getDb()->driver;
        $this->removeTables();

        return true;
    }

    // Protected Methods
    // =========================================================================

    /**
     * Creates the tables.
     *
     * @return bool
     */
    protected function createTables()
    {
        $tablesCreated = false;

        // gql_refresh_tokens table
        $tableSchema = Craft::$app->db->schema->getTableSchema('{{%gql_refresh_tokens}}');

        if ($tableSchema === null) {
            $tablesCreated = true;

            $this->createTable(
                '{{%gql_refresh_tokens}}',
                [
                    'id' => $this->integer()->notNull(),
                    'token' => $this->text()->notNull(),
                    'userId' => $this->integer()->notNull(),
                    'schemaId' => $this->integer()->notNull(),
                    'dateCreated' => $this->dateTime()->notNull(),
                    'dateUpdated' => $this->dateTime()->notNull(),
                    'expiryDate' => $this->dateTime()->notNull(),
                    'uid' => $this->uid(),
                    'PRIMARY KEY(id)',
                ]
            );
        }

        return $tablesCreated;
    }

    /**
     * Creates the indexes.
     */
    public function createIndexes()
    {
    }

    /**
     * Creates the foreign keys.
     *
     * @return void
     */
    protected function addForeignKeys()
    {
        // gql_refresh_tokens table
        $this->addForeignKey(
            $this->db->getForeignKeyName('{{%gql_refresh_tokens}}', 'id'),
            '{{%gql_refresh_tokens}}',
            'id',
            '{{%elements}}',
            'id',
            'CASCADE',
            null
        );

        $this->addForeignKey(
            $this->db->getForeignKeyName('{{%gql_refresh_tokens}}', 'userId'),
            '{{%gql_refresh_tokens}}',
            'userId',
            '{{%elements}}',
            'id',
            'CASCADE',
            null
        );
    }

    /**
     * Populates the DB with the default data.
     *
     * @return void
     */
    protected function insertDefaultData()
    {
    }

    /**
     * Removes the tables needed for the Records used by the plugin.
     *
     * @return void
     */
    protected function removeTables()
    {
        // gql_refresh_tokens table
        $this->dropTableIfExists('{{%gql_refresh_tokens}}');
    }
}

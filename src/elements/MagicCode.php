<?php

namespace jamesedmonston\graphqlauthentication\elements;

use Craft;
use craft\base\Element;
use craft\elements\actions\Delete;
use craft\elements\db\ElementQueryInterface;
use craft\services\Elements;
use craft\services\Gql;
use craft\services\Users;
use jamesedmonston\graphqlauthentication\elements\db\MagicCodeQuery;

class MagicCode extends Element
{
    public $code;
    public $userId;
    public $schemaId;
    public $expiryDate;

    public static function find(): ElementQueryInterface
    {
        return new MagicCodeQuery(static::class);
    }

    protected static function defineSources(string $context = null): array
    {
        return [
            [
                'key' => '*',
                'label' => Craft::t('graphql-authentication', 'Magic Codes'),
                'criteria' => [],
            ],
        ];
    }

    protected static function defineActions(string $source = null): array
    {
        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        return [
            $elementsService->createAction([
                'type' => Delete::class,
                'confirmationMessage' => Craft::t('app', 'Are you sure you want to delete the selected codes?'),
                'successMessage' => Craft::t('app', 'Codes deleted.'),
            ]),
        ];
    }

    protected static function defineTableAttributes(): array
    {
        return [
            'id' => Craft::t('graphql-authentication', 'ID'),
            'code' => Craft::t('graphql-authentication', 'Code'),
            'userId' => Craft::t('graphql-authentication', 'User'),
            'schemaName' => Craft::t('graphql-authentication', 'Schema'),
            'dateCreated' => Craft::t('graphql-authentication', 'Date Created'),
            'expiryDate' => Craft::t('graphql-authentication', 'Expiry Date'),
        ];
    }

    protected function tableAttributeHtml(string $attribute): string
    {
        switch ($attribute) {
            case 'code':
                return $this->code;

            case 'userId':
                /** @var Users */
                $usersService = Craft::$app->getUsers();
                $user = $usersService->getUserById($this->userId);
                return $user ? Craft::$app->getView()->renderTemplate('_elements/element', ['element' => $user]) : '';

            case 'schemaName':
                /** @var Gql */
                $gqlService = Craft::$app->getGql();
                $schema = $gqlService->getSchemaById($this->schemaId);
                return $schema->name ?? '';
        }

        return parent::tableAttributeHtml($attribute);
    }

    /**
     * @param bool $isNew
     *
     * @throws \yii\db\Exception
     */
    public function afterSave(bool $isNew): void
    {
        if ($isNew) {
            Craft::$app->db->createCommand()
                ->insert('{{%gql_magic_codes}}', [
                    'id' => $this->id,
                    'code' => $this->code,
                    'userId' => $this->userId,
                    'schemaId' => $this->schemaId,
                    'expiryDate' => $this->expiryDate,
                ])
                ->execute();
        } else {
            Craft::$app->db->createCommand()
                ->update('{{%gql_magic_codes}}', [
                    'code' => $this->code,
                    'userId' => $this->userId,
                    'schemaId' => $this->schemaId,
                    'expiryDate' => $this->expiryDate,
                ], ['id' => $this->id])
                ->execute();
        }

        parent::afterSave($isNew);
    }
}

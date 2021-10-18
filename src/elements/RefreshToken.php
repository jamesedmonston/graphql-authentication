<?php

namespace jamesedmonston\graphqlauthentication\elements;

use Craft;
use craft\base\Element;
use craft\elements\actions\Delete;
use craft\elements\db\ElementQueryInterface;
use craft\services\Elements;
use craft\services\Gql;
use craft\services\Users;
use jamesedmonston\graphqlauthentication\elements\db\RefreshTokenQuery;

class RefreshToken extends Element
{
    public $token;
    public $userId;
    public $schemaId;
    public $expiryDate;

    public static function find(): ElementQueryInterface
    {
        return new RefreshTokenQuery(static::class);
    }

    protected static function defineSources(string $context = null): array
    {
        return [
            [
                'key' => '*',
                'label' => Craft::t('graphql-authentication', 'Refresh Tokens'),
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
                'confirmationMessage' => Craft::t('app', 'Are you sure you want to delete the selected tokens?'),
                'successMessage' => Craft::t('app', 'Tokens deleted.'),
            ]),
        ];
    }

    protected static function defineTableAttributes(): array
    {
        return [
            'id' => Craft::t('graphql-authentication', 'ID'),
            'token' => Craft::t('graphql-authentication', 'Token'),
            'userId' => Craft::t('graphql-authentication', 'User'),
            'schemaName' => Craft::t('graphql-authentication', 'Schema'),
            'dateCreated' => Craft::t('graphql-authentication', 'Date Created'),
            'expiryDate' => Craft::t('graphql-authentication', 'Expiry Date'),
        ];
    }

    protected function tableAttributeHtml(string $attribute): string
    {
        switch ($attribute) {
            case 'token':
                return substr($this->token, 0, 10) . '...';

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
    public function afterSave(bool $isNew)
    {
        if ($isNew) {
            Craft::$app->db->createCommand()
                ->insert('{{%gql_refresh_tokens}}', [
                    'id' => $this->id,
                    'token' => $this->token,
                    'userId' => $this->userId,
                    'schemaId' => $this->schemaId,
                    'expiryDate' => $this->expiryDate,
                ])
                ->execute();
        } else {
            Craft::$app->db->createCommand()
                ->update('{{%gql_refresh_tokens}}', [
                    'token' => $this->token,
                    'userId' => $this->userId,
                    'schemaId' => $this->schemaId,
                    'expiryDate' => $this->expiryDate,
                ], ['id' => $this->id])
                ->execute();
        }

        parent::afterSave($isNew);
    }
}

<?php

namespace jamesedmonston\graphqlauthentication\elements\db;

use craft\elements\db\ElementQuery;
use craft\helpers\Db;

class RefreshTokenQuery extends ElementQuery
{
    public $token;
    public $userId;
    public $schemaId;
    public $expiryDate;

    public function token($value)
    {
        $this->token = $value;
        return $this;
    }

    public function userId($value)
    {
        $this->userId = $value;
        return $this;
    }

    public function schemaId($value)
    {
        $this->schemaId = $value;
        return $this;
    }

    public function expiryDate($value)
    {
        $this->expiryDate = $value;
        return $this;
    }

    protected function beforePrepare(): bool
    {
        $this->joinElementTable('gql_refresh_tokens');

        $this->query->select([
            'gql_refresh_tokens.token',
            'gql_refresh_tokens.userId',
            'gql_refresh_tokens.schemaId',
            'gql_refresh_tokens.expiryDate',
        ]);

        if ($this->token) {
            $this->subQuery->andWhere(Db::parseParam('gql_refresh_tokens.token', $this->token));
        }

        if ($this->userId) {
            $this->subQuery->andWhere(Db::parseParam('gql_refresh_tokens.userId', $this->userId));
        }

        if ($this->schemaId) {
            $this->subQuery->andWhere(Db::parseParam('gql_refresh_tokens.schemaId', $this->schemaId));
        }

        if ($this->expiryDate) {
            $this->subQuery->andWhere(Db::parseParam('gql_refresh_tokens.expiryDate', $this->expiryDate));
        }

        return parent::beforePrepare();
    }
}

<?php

namespace jamesedmonston\graphqlauthentication\elements\db;

use craft\elements\db\ElementQuery;
use craft\helpers\Db;

class MagicCodeQuery extends ElementQuery
{
    public $code;
    public $userId;
    public $schemaId;
    public $expiryDate;

    public function code($value)
    {
        $this->code = $value;
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
        $this->joinElementTable('gql_magic_codes');

        $this->query->select([
            'gql_magic_codes.code',
            'gql_magic_codes.userId',
            'gql_magic_codes.schemaId',
            'gql_magic_codes.expiryDate',
        ]);

        if ($this->code) {
            $this->subQuery->andWhere(Db::parseParam('gql_magic_codes.code', $this->code));
        }

        if ($this->userId) {
            $this->subQuery->andWhere(Db::parseParam('gql_magic_codes.userId', $this->userId));
        }

        if ($this->schemaId) {
            $this->subQuery->andWhere(Db::parseParam('gql_magic_codes.schemaId', $this->schemaId));
        }

        if ($this->expiryDate) {
            $this->subQuery->andWhere(Db::parseParam('gql_magic_codes.expiryDate', $this->expiryDate));
        }

        return parent::beforePrepare();
    }
}

<?php

namespace jamesedmonston\graphqlauthentication\models;

use craft\base\Model;

class Settings extends Model
{
    public $schemaId = null;
    public $expiration = null;
    public $setCookie = null;
    public $userGroup = null;
    public $entryQueries = null;
    public $entryMutations = null;
    public $assetQueries = null;
    public $assetMutations = null;

    public function rules()
    {
        return [
            [['schemaId', 'expiration'], 'required'],
            [['setCookie', 'userGroup', 'entryQueries', 'entryMutations', 'assetQueries', 'assetMutations'], 'default'],
        ];
    }
}

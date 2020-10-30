<?php

namespace jamesedmonston\graphqlauthentication\models;

use craft\base\Model;

class Settings extends Model
{
    public $schemaId = null;
    public $expiration = null;
    public $userGroup = null;
    public $queries = null;
    public $mutations = null;

    public function rules()
    {
        return [
            [['schemaId', 'expiration'], 'required'],
            [['userGroup', 'queries', 'mutations'], 'default'],
        ];
    }
}

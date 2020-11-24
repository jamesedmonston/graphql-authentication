<?php

namespace jamesedmonston\graphqlauthentication\models;

use craft\base\Model;

class Settings extends Model
{
    // Schemas
    public $permissionType = 'single';

    // Singular Schema
    public $schemaId = null;
    public $allowRegistration = true;
    public $userGroup = null;
    public $entryQueries = null;
    public $entryMutations = null;
    public $assetQueries = null;
    public $assetMutations = null;

    // Multiple Schemas
    public $granularSchemas = [];

    // Tokens
    public $expiration = null;
    public $setCookie = null;

    // Social
    public $googleClientId = null;
    public $allowedGoogleDomains = null;

    public function rules()
    {
        return [
            [['permissionType'], 'required'],
            [
                [
                    'schemaId',
                    'allowRegistration',
                    'userGroup',
                    'entryQueries',
                    'entryMutations',
                    'assetQueries',
                    'assetMutations',
                    'granularSchemas',
                    'expiration',
                    'setCookie',
                    'googleClientId',
                    'allowedGoogleDomains',
                ],
                'default',
            ],
        ];
    }
}

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
    public $tokenType = 'response';
    public $expiration = '1 week';
    public $setCookie = null;
    public $jwtExpiration = '30 minutes';
    public $jwtRefreshExpiration = '3 months';
    public $jwtSecretKey = null;
    public $sameSitePolicy = 'strict';

    // Social
    public $googleClientId = null;
    public $allowedGoogleDomains = null;

    public $facebookAppId = null;
    public $facebookAppSecret = null;
    public $facebookRedirectUrl = null;

    public $twitterApiKey = null;
    public $twitterApiKeySecret = null;
    public $twitterRedirectUrl = null;

    // Messages
    public $invalidHeader = 'Invalid Authorization Header';
    public $invalidSchema = 'No schema has been set for this user group';
    public $invalidRequest = 'Cannot validate request';
    public $invalidLogin = "We couldn't log you in with the provided details";
    public $invalidPasswordMatch = 'New passwords do not match';
    public $invalidPasswordUpdate = "We couldn't update the password with the provided details";
    public $invalidUserUpdate = "We couldn't update the user with the provided details";
    public $invalidOauthToken = 'Invalid OAuth Token';

    public $tokenNotFound = "We couldn't find any matching tokens";
    public $userNotFound = "We couldn't find any matching users";
    public $entryNotFound = "We couldn't find any matching entries";
    public $assetNotFound = "We couldn't find any matching assets";
    public $emailNotInScope = 'No email in scope';

    public $forbiddenMutation = "User doesn't have permission to perform this mutation";

    public $googleTokenIdInvalid = 'Invalid Google Token ID';
    public $googleEmailMismatch = "Email address doesn't match allowed Google domains";

    public function rules()
    {
        return [
            [
                [
                    'permissionType',
                    'tokenType',
                    'invalidHeader',
                    'invalidSchema',
                    'invalidRequest',
                    'invalidLogin',
                    'invalidPasswordMatch',
                    'invalidPasswordUpdate',
                    'invalidUserUpdate',
                    'invalidOauthToken',
                    'tokenNotFound',
                    'userNotFound',
                    'entryNotFound',
                    'assetNotFound',
                    'emailNotInScope',
                    'forbiddenMutation',
                    'googleTokenIdInvalid',
                    'googleEmailMismatch',
                ],
                'required',
            ],
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
                    'jwtExpiration',
                    'jwtRefreshExpiration',
                    'jwtSecretKey',
                    'sameSitePolicy',
                    'googleClientId',
                    'allowedGoogleDomains',
                    'facebookAppId',
                    'facebookAppSecret',
                    'facebookRedirectUrl',
                    'twitterApiKey',
                    'twitterApiKeySecret',
                    'twitterRedirectUrl',
                ],
                'default',
            ],
        ];
    }
}

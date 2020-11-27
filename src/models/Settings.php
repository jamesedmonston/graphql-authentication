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
    public $sameSitePolicy = 'strict';

    // Social
    public $googleClientId = null;
    public $allowedGoogleDomains = null;
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

    public $tokenNotFound = "We couldn't find any matching tokens";
    public $userNotFound = "We couldn't find any matching users";
    public $entryNotFound = "We couldn't find any matching entries";
    public $assetNotFound = "We couldn't find any matching assets";

    public $forbiddenMutation = "User doesn't have permission to perform this mutation";

    public $googleClientNotFound = 'No Google Client ID exists';
    public $googleTokenIdInvalid = 'Invalid Google Token ID';
    public $googleEmailNotInScope = 'No email in scope';
    public $googleEmailMismatch = "Email address doesn't match allowed Google domains";

    public $twitterApiKeyNotFound = 'No Twitter API key exists';
    public $twitterApiKeySecretNotFound = 'No Twitter API key secret exists';
    public $twitterRedirectUrlNotFound = 'No Twitter redirect URL exists';
    public $twitterEmailNotInScope = 'No email in scope';
    public $twitterInvalidOauthToken = 'Invalid OAuth Token';
    public $twitterInvalidGenerate = "Couldn't generate Twitter OAuth URL";

    public function rules()
    {
        return [
            [
                [
                    'permissionType',
                    'invalidHeader',
                    'invalidSchema',
                    'invalidRequest',
                    'invalidLogin',
                    'invalidPasswordMatch',
                    'invalidPasswordUpdate',
                    'invalidUserUpdate',
                    'tokenNotFound',
                    'userNotFound',
                    'entryNotFound',
                    'assetNotFound',
                    'forbiddenMutation',
                    'googleClientNotFound',
                    'googleTokenIdInvalid',
                    'googleEmailNotInScope',
                    'googleEmailMismatch',
                    'twitterApiKeyNotFound',
                    'twitterApiKeySecretNotFound',
                    'twitterRedirectUrlNotFound',
                    'twitterEmailNotInScope',
                    'twitterInvalidOauthToken',
                    'twitterInvalidGenerate',
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
                    'sameSitePolicy',
                    'googleClientId',
                    'allowedGoogleDomains',
                ],
                'default',
            ],
        ];
    }
}

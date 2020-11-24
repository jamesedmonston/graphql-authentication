<?php
/**
 * GraphQL Authentication plugin for Craft CMS 3.5
 *
 * GraphQL authentication for your headless Craft CMS applications.
 *
 * @link      https://github.com/jamesedmonston/graphql-authentication
 * @copyright Copyright (c) 2020 James Edmonston
 */

namespace jamesedmonston\graphqlauthentication;

use Craft;
use craft\base\Plugin;
use craft\helpers\StringHelper;
use craft\helpers\UrlHelper;
use jamesedmonston\graphqlauthentication\models\Settings;
use jamesedmonston\graphqlauthentication\services\RestrictionService;
use jamesedmonston\graphqlauthentication\services\SocialService;
use jamesedmonston\graphqlauthentication\services\TokenService;
use jamesedmonston\graphqlauthentication\services\UserService;

/**
 * Class GraphqlAuthentication
 *
 * @author    James Edmonston
 * @package   GraphqlAuthentication
 * @since     1.0.0
 *
 */

class GraphqlAuthentication extends Plugin
{
    // Static Properties
    // =========================================================================

    /**
     * @var GraphqlAuthentication
     */
    public static $plugin;

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public $schemaVersion = '1.0.0';

    /**
     * @var bool
     */
    public $hasCpSettings = true;

    /**
     * @var bool
     */
    public $hasCpSection = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();
        self::$plugin = $this;

        $this->setComponents([
            'token' => TokenService::class,
            'user' => UserService::class,
            'restriction' => RestrictionService::class,
            'social' => SocialService::class,
        ]);

        $this->token->init();
        $this->user->init();
        $this->restriction->init();
        $this->social->init();
    }

    public function isGraphiqlRequest(): bool
    {
        return StringHelper::contains((Craft::$app->getRequest()->getReferrer() ?? '') . 'graphiql', UrlHelper::cpUrl() . 'graphiql');
    }

    // Protected Methods
    // =========================================================================

    protected function createSettingsModel()
    {
        return new Settings();
    }

    protected function settingsHtml()
    {
        $gql = Craft::$app->getGql();
        $sections = Craft::$app->getSections()->getAllSections();
        $volumes = Craft::$app->getVolumes()->getAllVolumes();
        $settings = $this->getSettings();
        $userGroups = Craft::$app->getUserGroups()->getAllGroups();
        $schemas = $gql->getSchemas();
        $publicSchema = $gql->getPublicSchema();

        $userOptions = [
            [
                'label' => '',
                'value' => '',
            ],
        ];

        foreach ($userGroups as $userGroup) {
            $userOptions[] = [
                'label' => $userGroup->name,
                'value' => $userGroup->id,
            ];
        }

        $schemaOptions = [
            [
                'label' => '',
                'value' => '',
            ],
        ];

        foreach ($schemas as $schema) {
            if ($publicSchema && $schema->id === $publicSchema->id) {
                continue;
            }

            $schemaOptions[] = [
                'label' => $schema->name,
                'value' => $schema->id,
            ];
        }

        $entryQueries = null;
        $entryMutations = null;
        $assetQueries = null;
        $assetMutations = null;

        if ($settings->schemaId) {
            $selectedSchema = $gql->getSchemaById($settings->schemaId);

            $entryQueries = [];
            $entryMutations = [];

            $scopes = array_filter($selectedSchema->scope, function ($key) {
                return StringHelper::contains($key, 'sections');
            });

            foreach ($scopes as $scope) {
                $scopeId = explode(':', explode('.', $scope)[1])[0];

                $section = array_values(array_filter($sections, function ($type) use ($scopeId) {
                    return $type['uid'] === $scopeId;
                }))[0];

                if ($section->type === 'single') {
                    continue;
                }

                $name = $section->name;
                $handle = $section->handle;

                if (StringHelper::contains($scope, ':read')) {
                    if (isset($entryQueries[$name])) {
                        continue;
                    }

                    $entryQueries[$name] = [
                        'label' => $name,
                        'handle' => $handle,
                    ];

                    continue;
                }

                if (isset($entryMutations[$name])) {
                    continue;
                }

                $entryMutations[$name] = [
                    'label' => $name,
                    'handle' => $handle,
                ];
            }

            $assetQueries = [];
            $assetMutations = [];

            $scopes = array_filter($selectedSchema->scope, function ($key) {
                return StringHelper::contains($key, 'volumes');
            });

            foreach ($scopes as $scope) {
                $scopeId = explode(':', explode('.', $scope)[1])[0];

                $volume = array_values(array_filter($volumes, function ($type) use ($scopeId) {
                    return $type['uid'] === $scopeId;
                }))[0];

                $name = $volume->name;
                $handle = $volume->handle;

                if (StringHelper::contains($scope, ':read')) {
                    if (isset($assetQueries[$name])) {
                        continue;
                    }

                    $assetQueries[$name] = [
                        'label' => $name,
                        'handle' => $handle,
                    ];

                    continue;
                }

                if (isset($assetMutations[$name])) {
                    continue;
                }

                $assetMutations[$name] = [
                    'label' => $name,
                    'handle' => $handle,
                ];
            }
        }

        return Craft::$app->getView()->renderTemplate('graphql-authentication/index', [
            'settings' => $settings,
            'userOptions' => $userOptions,
            'schemaOptions' => $schemaOptions,
            'entryQueries' => $entryQueries,
            'entryMutations' => $entryMutations,
            'assetQueries' => $assetQueries,
            'assetMutations' => $assetMutations,
        ]);
    }
}

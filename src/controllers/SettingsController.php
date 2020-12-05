<?php

namespace jamesedmonston\graphqlauthentication\controllers;

use Craft;
use craft\helpers\StringHelper;
use craft\models\GqlSchema;
use craft\web\Controller;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\web\HttpException;

class SettingsController extends Controller
{
    /**
     * @throws HttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function actionIndex()
    {
        $currentUser = Craft::$app->getUser();

        if (!$currentUser->getIsAdmin()) {
            throw new HttpException(403);
        }

        $settings = GraphqlAuthentication::$plugin->getSettings();
        $settings->validate();

        $namespace = 'settings';
        $fullPageForm = true;

        $crumbs = [
            ['label' => 'Settings', 'url' => '/settings'],
        ];

        $tabs = [
            [
                'label' => 'Users',
                'url' => "#settings-users",
                'class' => null,
            ],
            [
                'label' => 'Tokens',
                'url' => "#settings-tokens",
                'class' => null,
            ],
            [
                'label' => 'Social',
                'url' => "#settings-social",
                'class' => null,
            ],
            [
                'label' => 'Messages',
                'url' => "#settings-messages",
                'class' => null,
            ],
        ];

        $userGroups = Craft::$app->getUserGroups()->getAllGroups();

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

        $gql = Craft::$app->getGql();
        $schemas = $gql->getSchemas();
        $publicSchema = $gql->getPublicSchema();

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

        asort($schemaOptions);

        $entryQueries = null;
        $entryMutations = null;
        $assetQueries = null;
        $assetMutations = null;

        if ($settings->permissionType === 'single' && $settings->schemaId) {
            $schemaPermissions = $this->_getSchemaPermissions($gql->getSchemaById($settings->schemaId));
            $entryQueries = $schemaPermissions['entryQueries'];
            $entryMutations = $schemaPermissions['entryMutations'];
            $assetQueries = $schemaPermissions['assetQueries'];
            $assetMutations = $schemaPermissions['assetMutations'];
        }

        if ($settings->permissionType === 'multiple') {
            foreach ($userGroups as $userGroup) {
                $schemaId = $settings->granularSchemas['group-' . $userGroup->id]['schemaId'] ?? null;

                if (!$schemaId) {
                    continue;
                }

                $schema = $gql->getSchemaById($schemaId);

                if ($schema) {
                    $schemaPermissions = $this->_getSchemaPermissions($schema);
                    $entryQueries['group-' . $userGroup->id] = $schemaPermissions['entryQueries'];
                    $entryMutations['group-' . $userGroup->id] = $schemaPermissions['entryMutations'];
                    $assetQueries['group-' . $userGroup->id] = $schemaPermissions['assetQueries'];
                    $assetMutations['group-' . $userGroup->id] = $schemaPermissions['assetMutations'];
                }
            }
        }

        if (!$settings->jwtSecretKey) {
            $settings->jwtSecretKey = Craft::$app->getSecurity()->generateRandomString(32);
        }

        $this->renderTemplate('graphql-authentication/settings', compact(
            'settings',
            'namespace',
            'fullPageForm',
            'crumbs',
            'tabs',
            'settings',
            'userOptions',
            'schemaOptions',
            'entryQueries',
            'entryMutations',
            'assetQueries',
            'assetMutations'
        ));
    }

    protected function _getSchemaPermissions(GqlSchema $schema)
    {
        $sections = Craft::$app->getSections()->getAllSections();
        $volumes = Craft::$app->getVolumes()->getAllVolumes();

        $entryQueries = [];
        $entryMutations = [];

        $scopes = array_filter($schema->scope, function ($key) {
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

        $scopes = array_filter($schema->scope, function ($key) {
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

        return compact(
            'entryQueries',
            'entryMutations',
            'assetQueries',
            'assetMutations'
        );
    }
}

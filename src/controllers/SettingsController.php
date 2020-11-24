<?php

namespace jamesedmonston\graphqlauthentication\controllers;

use Craft;
use craft\helpers\StringHelper;
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
        $currentUser = \Craft::$app->user;

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
        ];

        $gql = Craft::$app->getGql();
        $sections = Craft::$app->getSections()->getAllSections();
        $volumes = Craft::$app->getVolumes()->getAllVolumes();
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

        $this->renderTemplate('graphql-authentication/settings', array_merge(
            compact(
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
                'assetMutations',
            )
        ));
    }
}

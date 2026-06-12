<?php

namespace jamesedmonston\graphqlauthentication\controllers;

use Craft;
use craft\helpers\StringHelper;
use craft\helpers\UrlHelper;
use craft\models\GqlSchema;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\web\Controller;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\web\HttpException;
use yii\web\NotFoundHttpException;
use yii\web\Response;

class SettingsController extends Controller
{
    /**
     * @throws HttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function actionIndex()
    {
        if (!Craft::$app->getUser()->getIsAdmin()) {
            throw new HttpException(403);
        }

        $settings = GraphqlAuthentication::$settings;
        $settings->validate();

        $namespace = 'settings';
        $fullPageForm = true;

        $crumbs = [
            ['label' => 'Settings', 'url' => UrlHelper::cpUrl('settings')],
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
                'label' => 'Fields',
                'url' => "#settings-fields",
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

        $userGroupsService = Craft::$app->getUserGroups();
        $userGroups = $userGroupsService->getAllGroups();

        $userOptions = [
            [
                'label' => '-',
                'value' => '',
            ],
        ];

        foreach ($userGroups as $userGroup) {
            $userOptions[] = [
                'label' => $userGroup->name,
                'value' => $userGroup->id,
            ];
        }

        $sitesService = Craft::$app->getSites();
        $sites = $sitesService->getAllSites();

        $siteOptions = [
            [
                'label' => 'All Sites',
                'value' => '',
            ],
        ];

        foreach ($sites as $site) {
            $siteOptions[] = [
                'label' => $site->name,
                'value' => $site->id,
            ];
        }

        $gqlService = Craft::$app->getGql();
        $schemas = $gqlService->getSchemas();
        $publicSchema = $gqlService->getPublicSchema();

        $schemaOptions = [
            [
                'label' => '-',
                'value' => '',
            ],
        ];

        foreach ($schemas as $schema) {
            $schemaOptions[] = [
                'label' => $schema->isPublic ? 'Public' : $schema->name,
                'value' => $schema->isPublic ? 'public' : $schema->name,
            ];
        }

        asort($schemaOptions);

        $entryQueries = null;
        $entryMutations = null;
        $assetQueries = null;
        $assetMutations = null;
        $userGroupsTable = [];

        if ($settings->permissionType === 'single' && $settings->schemaName) {
            if ($settings->schemaName === 'public') {
                // For public schema, get it directly
                $schemaPermissions = $this->_getSchemaPermissions($publicSchema);
            } else {
                // For named schemas, find by name
                $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();
                $schemaPermissions = $this->_getSchemaPermissions($gqlService->getSchemaById($schemaId));
            }
            $entryQueries = $schemaPermissions['entryQueries'];
            $entryMutations = $schemaPermissions['entryMutations'];
            $assetQueries = $schemaPermissions['assetQueries'];
            $assetMutations = $schemaPermissions['assetMutations'];
        }

        if ($settings->permissionType === 'multiple') {
            $userGroupsTable = [];
            $schemaLabelMap = [];

            foreach ($schemaOptions as $opt) {
                $schemaLabelMap[$opt['value']] = $opt['label'];
            }

            $siteLabelMap = [];

            foreach ($siteOptions as $opt) {
                $siteLabelMap[$opt['value']] = $opt['label'];
            }

            foreach ($userGroups as $userGroup) {
                $groupKey = 'group-' . $userGroup->id;
                $groupData = $settings->granularSchemas[$groupKey] ?? [];
                $schemaName = $groupData['schemaName'] ?? '';
                $siteId = $groupData['siteId'] ?? '';
                $allowRegistration = !empty($groupData['allowRegistration']);
                $schemaLabel = $schemaLabelMap[$schemaName] ?? ($schemaName ?: '-');
                $siteLabel = $siteId === '' ? 'All Sites' : ($siteLabelMap[$siteId] ?? '-');
                $userGroupsTable[] = [
                    'id' => $userGroup->id,
                    'name' => $userGroup->name,
                    'groupKey' => $groupKey,
                    'schemaLabel' => $schemaLabel,
                    'siteLabel' => $siteLabel,
                    'registrationLabel' => $allowRegistration ? 'Enabled' : 'Disabled',
                ];
            }

            foreach ($userGroups as $userGroup) {
                $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;

                if (!$schemaName) {
                    continue;
                }

                if ($schemaName === 'public') {
                    $schema = $publicSchema;
                } else {
                    $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();
                    if (!$schemaId) {
                        continue;
                    }
                    $schema = $gqlService->getSchemaById($schemaId);
                }

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

        $fieldsServices = Craft::$app->getFields();
        $fields = $fieldsServices->getAllFields();

        $this->renderTemplate('graphql-authentication/settings', compact(
            'settings',
            'namespace',
            'fullPageForm',
            'crumbs',
            'tabs',
            'settings',
            'userOptions',
            'userGroupsTable',
            'siteOptions',
            'schemaOptions',
            'entryQueries',
            'entryMutations',
            'assetQueries',
            'assetMutations',
            'fields'
        ));
    }

    protected function _getSchemaPermissions(GqlSchema $schema)
    {
        $entriesService = Craft::$app->getEntries();
        $sections = $entriesService->getAllSections();

        $volumesService = Craft::$app->getVolumes();
        $volumes = $volumesService->getAllVolumes();

        $entryQueries = [];
        $entryMutations = [];

        $scopes = array_filter($schema->scope, function($key) {
            return StringHelper::contains($key, 'sections');
        });

        foreach ($scopes as $scope) {
            $scopeId = explode(':', explode('.', $scope)[1])[0];

            $section = array_values(array_filter($sections, function($type) use ($scopeId) {
                return $type['uid'] === $scopeId;
            }))[0] ?? null;

            if (!$section) {
                continue;
            }

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

        $scopes = array_filter($schema->scope, function($key) {
            return StringHelper::contains($key, 'volumes');
        });

        foreach ($scopes as $scope) {
            $scopeId = explode(':', explode('.', $scope)[1])[0];

            $volume = array_values(array_filter($volumes, function($type) use ($scopeId) {
                return $type['uid'] === $scopeId;
            }))[0] ?? null;

            if (!$volume) {
                continue;
            }

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

    /**
     * Edit a single user group's GraphQL authentication settings.
     *
     * @param int $id User group ID
     * @return Response
     * @throws HttpException
     * @throws NotFoundHttpException
     * @throws \yii\base\InvalidConfigException
     */
    public function actionEditUserGroup(int $id): Response
    {
        if (!Craft::$app->getUser()->getIsAdmin()) {
            throw new HttpException(403);
        }

        $userGroupsService = Craft::$app->getUserGroups();
        $userGroup = $userGroupsService->getGroupById($id);
        if ($userGroup === null) {
            throw new NotFoundHttpException('User group not found');
        }

        $settings = GraphqlAuthentication::$settings;
        $groupKey = 'group-' . $id;
        $groupSettings = $settings->granularSchemas[$groupKey] ?? [];

        $sitesService = Craft::$app->getSites();
        $sites = $sitesService->getAllSites();
        $siteOptions = [['label' => 'All Sites', 'value' => '']];
        foreach ($sites as $site) {
            $siteOptions[] = ['label' => $site->name, 'value' => $site->id];
        }

        $gqlService = Craft::$app->getGql();
        $schemas = $gqlService->getSchemas();
        $publicSchema = $gqlService->getPublicSchema();
        $schemaOptions = [['label' => '-', 'value' => '']];
        foreach ($schemas as $schema) {
            $schemaOptions[] = [
                'label' => $schema->isPublic ? 'Public' : $schema->name,
                'value' => $schema->isPublic ? 'public' : $schema->name,
            ];
        }
        asort($schemaOptions);

        $entryQueries = [];
        $entryMutations = [];
        $assetQueries = [];
        $assetMutations = [];
        $schemaName = $groupSettings['schemaName'] ?? null;
        if ($schemaName) {
            if ($schemaName === 'public') {
                $schema = $publicSchema;
            } else {
                $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();
                $schema = $schemaId ? $gqlService->getSchemaById($schemaId) : null;
            }
            if ($schema) {
                $perms = $this->_getSchemaPermissions($schema);
                $entryQueries = $perms['entryQueries'];
                $entryMutations = $perms['entryMutations'];
                $assetQueries = $perms['assetQueries'];
                $assetMutations = $perms['assetMutations'];
            }
        }

        $crumbs = [
            ['label' => 'Settings', 'url' => UrlHelper::cpUrl('settings')],
            ['label' => 'GraphQL Authentication', 'url' => UrlHelper::cpUrl('graphql-authentication/settings')],
            ['label' => $userGroup->name, 'url' => UrlHelper::cpUrl('graphql-authentication/settings/user-group/' . $id)],
        ];

        return $this->renderTemplate('graphql-authentication/settings/user-group-edit', compact(
            'userGroup',
            'groupKey',
            'groupSettings',
            'schemaOptions',
            'siteOptions',
            'entryQueries',
            'entryMutations',
            'assetQueries',
            'assetMutations',
            'crumbs'
        ));
    }

    /**
     * Save a single user group's GraphQL authentication settings.
     *
     * @return Response|null
     * @throws HttpException
     */
    public function actionSaveUserGroup(): ?Response
    {
        $this->requirePostRequest();
        if (!Craft::$app->getUser()->getIsAdmin()) {
            throw new HttpException(403);
        }

        $userId = $this->request->getBodyParam('userGroupId');
        if ($userId === null || $userId === '') {
            return $this->redirect(UrlHelper::cpUrl('graphql-authentication/settings'));
        }
        $id = (int) $userId;
        $groupKey = 'group-' . $id;

        $settingsData = $this->request->getBodyParam('settings', []);
        $submittedGroup = $settingsData['granularSchemas'][$groupKey] ?? [];
        if (empty($submittedGroup)) {
            return $this->redirect(UrlHelper::cpUrl('graphql-authentication/settings'));
        }

        $plugin = GraphqlAuthentication::$plugin;
        $currentSettings = $plugin->getSettings();
        $granularSchemas = $currentSettings->granularSchemas ?? [];
        $currentGroupSettings = $granularSchemas[$groupKey] ?? [];
        $granularSchemas[$groupKey] = array_merge(
            $currentGroupSettings,
            [
                'schemaName' => array_key_exists('schemaName', $submittedGroup)
                    ? $submittedGroup['schemaName']
                    : ($currentGroupSettings['schemaName'] ?? null),
                'allowRegistration' => array_key_exists('allowRegistration', $submittedGroup)
                    ? !empty($submittedGroup['allowRegistration'])
                    : !empty($currentGroupSettings['allowRegistration']),
                'siteId' => array_key_exists('siteId', $submittedGroup)
                    ? $submittedGroup['siteId']
                    : ($currentGroupSettings['siteId'] ?? null),
                'entryQueries' => array_key_exists('entryQueries', $submittedGroup)
                    ? $submittedGroup['entryQueries']
                    : ($currentGroupSettings['entryQueries'] ?? []),
                'entryMutations' => array_key_exists('entryMutations', $submittedGroup)
                    ? $submittedGroup['entryMutations']
                    : ($currentGroupSettings['entryMutations'] ?? []),
                'assetQueries' => array_key_exists('assetQueries', $submittedGroup)
                    ? $submittedGroup['assetQueries']
                    : ($currentGroupSettings['assetQueries'] ?? []),
                'assetMutations' => array_key_exists('assetMutations', $submittedGroup)
                    ? $submittedGroup['assetMutations']
                    : ($currentGroupSettings['assetMutations'] ?? []),
            ]
        );

        $toSave = $currentSettings->toArray();
        $toSave['granularSchemas'] = $granularSchemas;
        $success = Craft::$app->getPlugins()->savePluginSettings($plugin, $toSave);

        if ($success) {
            Craft::$app->getSession()->setNotice(Craft::t('app', 'Plugin settings saved.'));
        } else {
            Craft::$app->getSession()->setError(Craft::t('app', 'Couldn’t save plugin settings.'));
        }

        return $this->redirect(UrlHelper::cpUrl('graphql-authentication/settings'));
    }
}

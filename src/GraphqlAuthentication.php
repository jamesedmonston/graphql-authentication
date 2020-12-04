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
use craft\events\RegisterCpNavItemsEvent;
use craft\events\RegisterUrlRulesEvent;
use craft\helpers\UrlHelper;
use craft\web\twig\variables\Cp;
use craft\web\UrlManager;
use jamesedmonston\graphqlauthentication\models\Settings;
use jamesedmonston\graphqlauthentication\services\RestrictionService;
use jamesedmonston\graphqlauthentication\services\SocialService;
use jamesedmonston\graphqlauthentication\services\TokenService;
use jamesedmonston\graphqlauthentication\services\UserService;
use yii\base\Event;

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
    public $schemaVersion = '1.1.0';

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

        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            [$this, 'onRegisterCPUrlRules']
        );

        if ($this->getSettings()->tokenType === 'jwt') {
            Event::on(
                Cp::class,
                Cp::EVENT_REGISTER_CP_NAV_ITEMS,
                function (RegisterCpNavItemsEvent $event) {
                    $event->navItems[] = [
                        'url' => 'graphql-authentication/refresh-tokens',
                        'label' => 'JWT Refresh Tokens',
                        'icon' => '@jamesedmonston/graphqlauthentication/icon.svg',
                    ];
                }
            );
        }
    }

    // Settings
    // =========================================================================

    protected function createSettingsModel(): Settings
    {
        return new Settings();
    }

    public function getSettingsResponse()
    {
        Craft::$app->controller->redirect(UrlHelper::cpUrl('graphql-authentication/settings'));
    }

    public function onRegisterCPUrlRules(RegisterUrlRulesEvent $event)
    {
        $event->rules['POST graphql-authentication/settings'] = 'graphql-authentication/settings/save';
        $event->rules['graphql-authentication/settings'] = 'graphql-authentication/settings/index';
    }
}

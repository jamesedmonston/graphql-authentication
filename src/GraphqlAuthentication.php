<?php
/**
 * GraphQL Authentication plugin for Craft CMS 4.0
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
use craft\helpers\App;
use craft\helpers\UrlHelper;
use craft\web\twig\variables\Cp;
use craft\web\UrlManager;
use jamesedmonston\graphqlauthentication\models\Settings;
use jamesedmonston\graphqlauthentication\services\AppleService;
use jamesedmonston\graphqlauthentication\services\ErrorService;
use jamesedmonston\graphqlauthentication\services\FacebookService;
use jamesedmonston\graphqlauthentication\services\GoogleService;
use jamesedmonston\graphqlauthentication\services\MagicService;
use jamesedmonston\graphqlauthentication\services\MicrosoftService;
use jamesedmonston\graphqlauthentication\services\RestrictionService;
use jamesedmonston\graphqlauthentication\services\SocialService;
use jamesedmonston\graphqlauthentication\services\TokenService;
use jamesedmonston\graphqlauthentication\services\TwitterService;
use jamesedmonston\graphqlauthentication\services\TwoFactorService;
use jamesedmonston\graphqlauthentication\services\UserService;
use yii\base\Event;

/**
 * Class GraphqlAuthentication
 *
 * @author    James Edmonston
 * @package   GraphqlAuthentication
 * @since     1.0.0
 *
 * @property TokenService $token
 * @property UserService $user
 * @property RestrictionService $restriction
 * @property SocialService $social
 * @property GoogleService $google
 * @property FacebookService $facebook
 * @property TwitterService $twitter
 * @property AppleService $apple
 * @property MicrosoftService $microsoft
 * @property MagicService $magic
 * @property TwoFactorService $twoFactor
 * @property ErrorService $error
 * @method Settings getSettings()
 */

class GraphqlAuthentication extends Plugin
{
    // Static Properties
    // =========================================================================

    /**
     * @var GraphqlAuthentication
     */
    public static $plugin;

    /**
     * @var TokenService
     */
    public static $tokenService;

    /**
     * @var UserService
     */
    public static $userService;

    /**
     * @var RestrictionService
     */
    public static $restrictionService;

    /**
     * @var SocialService
     */
    public static $socialService;

    /**
     * @var GoogleService
     */
    public static $googleService;

    /**
     * @var FacebookService
     */
    public static $facebookService;

    /**
     * @var TwitterService
     */
    public static $twitterService;

    /**
     * @var AppleService
     */
    public static $appleService;

    /**
     * @var MicrosoftService
     */
    public static $microsoftService;

    /**
     * @var MagicService
     */
    public static $magicService;

    /**
     * @var TwoFactorService
     */
    public static $twoFactorService;

    /**
     * @var ErrorService
     */
    public static $errorService;

    /**
     * @var Settings
     */
    public static $settings;

    // Public Properties
    // =========================================================================

    /**
     * @var string
     */
    public string $schemaVersion = '1.3.0';

    /**
     * @var bool
     */
    public bool $hasCpSettings = true;

    /**
     * @var bool
     */
    public bool $hasCpSection = false;

    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        $this->setComponents([
            'token' => TokenService::class,
            'user' => UserService::class,
            'restriction' => RestrictionService::class,
            'social' => SocialService::class,
            'google' => GoogleService::class,
            'facebook' => FacebookService::class,
            'twitter' => TwitterService::class,
            'apple' => AppleService::class,
            'microsoft' => MicrosoftService::class,
            'magic' => MagicService::class,
            'twoFactor' => TwoFactorService::class,
            'error' => ErrorService::class,
        ]);

        $this->token->init();
        $this->user->init();
        $this->restriction->init();
        $this->social->init();
        $this->google->init();
        $this->facebook->init();
        $this->twitter->init();
        $this->apple->init();
        $this->microsoft->init();
        $this->magic->init();
        $this->error->init();

        self::$plugin = $this;
        self::$tokenService = $this->token;
        self::$userService = $this->user;
        self::$restrictionService = $this->restriction;
        self::$socialService = $this->social;
        self::$googleService = $this->google;
        self::$facebookService = $this->facebook;
        self::$twitterService = $this->twitter;
        self::$appleService = $this->apple;
        self::$microsoftService = $this->microsoft;
        self::$errorService = $this->error;
        self::$magicService = $this->magic;
        self::$settings = $this->getSettings();

        if (Craft::$app->plugins->isPluginEnabled('two-factor-authentication')) {
            $this->twoFactor->init();
            self::$twoFactorService = $this->twoFactor;
        }

        Event::on(
            UrlManager::class,
            UrlManager::EVENT_REGISTER_CP_URL_RULES,
            [$this, 'onRegisterCPUrlRules']
        );

        Event::on(
            Cp::class,
            Cp::EVENT_REGISTER_CP_NAV_ITEMS,
            [$this, 'onRegisterCPNavItems']
        );
    }

    // Settings
    // =========================================================================

    protected function createSettingsModel(): ?\craft\base\Model
    {
        return new Settings();
    }

    public function getSettingsResponse(): mixed
    {
        return Craft::$app->controller->redirect(UrlHelper::cpUrl('graphql-authentication/settings'));
    }

    public function onRegisterCPUrlRules(RegisterUrlRulesEvent $event)
    {
        if (Craft::$app->getUser()->getIsAdmin()) {        
            $event->rules['POST graphql-authentication/settings'] = 'graphql-authentication/settings/save';
            $event->rules['graphql-authentication/settings'] = 'graphql-authentication/settings/index';
        }
    }

    public function onRegisterCPNavItems(RegisterCpNavItemsEvent $event)
    {
        if (Craft::$app->getUser()->getIsAdmin()) {
            $event->navItems[] = [
                'url' => 'graphql-authentication/refresh-tokens',
                'label' => 'JWT Refresh Tokens',
                'icon' => '@jamesedmonston/graphqlauthentication/icon.svg',
            ];

            if (self::$settings->allowMagicAuthentication) {
                $event->navItems[] = [
                    'url' => 'graphql-authentication/magic-codes',
                    'label' => 'JWT Magic Codes',
                    'icon' => '@jamesedmonston/graphqlauthentication/icon.svg',
                ];
            }
        }
    }

    public function getSettingsData(string $setting): string
    {
        if ($value = App::parseEnv($setting)) {
            return $value;
        }

        return $setting;
    }
}

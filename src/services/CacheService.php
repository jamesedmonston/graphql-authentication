<?php

namespace jamesedmonston\graphqlauthentication\services;

use craft\base\Component;
use craft\helpers\StringHelper;
use craft\services\Gql;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use Throwable;
use yii\base\Event;

class CacheService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        Event::on(
            Gql::class,
            Gql::EVENT_BEFORE_EXECUTE_GQL_QUERY,
            [$this, 'injectUniqueCache']
        );
    }

    public function injectUniqueCache(Event $event)
    {
        if (!GraphqlAuthentication::$plugin->getInstance()->restriction->shouldRestrictRequests()) {
            return;
        }

        try {
            $tokenService = GraphqlAuthentication::$plugin->getInstance()->token;
            $token = $tokenService->getHeaderToken();
            $cacheKey = $token->accessToken;

            if (StringHelper::contains($token->name, 'user-')) {
                $cacheKey = 'user-' . $tokenService->getUserFromToken()->id;
            }

            $event->variables['gql_cacheKey'] = $cacheKey;
        } catch (Throwable $e) {}
    }

}

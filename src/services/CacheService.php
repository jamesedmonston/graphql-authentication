<?php

namespace jamesedmonston\graphqlauthentication\services;

use craft\base\Component;
use craft\helpers\StringHelper;
use craft\services\Gql;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
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

    /**
     * Injects a per-user query cache
     *
     * @param Event $event
     */
    public function injectUniqueCache(Event $event)
    {
        $tokenService = GraphqlAuthentication::$plugin->getInstance()->token;

        if (!$token = $tokenService->getHeaderToken()) {
            return;
        }

        $cacheKey = $token->accessToken;

        if (StringHelper::contains($token->name, 'user-')) {
            $cacheKey = 'user-' . $tokenService->getUserIdFromToken($token);
        }

        $event->variables['gql_cacheKey'] = $cacheKey;
    }
}

<?php

namespace jamesedmonston\graphqlauthentication\gql;

use craft\gql\GqlEntityRegistry;
use GraphQL\Type\Definition\EnumType;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

class Platform extends ObjectType
{
    /**
     * @return string
     */
    public static function getName(): string
    {
        return 'Platform';
    }

    /**
     * @return Type
     */
    public static function getType(): Type
    {
        if ($type = GqlEntityRegistry::getEntity(static::getName())) {
            return $type;
        }

        $settings = GraphqlAuthentication::$settings;
        $values = [];

        if ((bool) $settings->appleClientId && (bool) $settings->appleClientSecret) {
            $values['NATIVE'] = [
                'value' => 'native',
            ];
        }

        if ((bool) $settings->appleServiceId && (bool) $settings->appleServiceSecret && (bool) $settings->appleRedirectUrl) {
            $values['WEB'] = [
                'value' => 'web',
            ];
        }

        return GqlEntityRegistry::createEntity(static::getName(), new EnumType([
            'name' => static::getName(),
            'values' => $values,
        ]));
    }
}

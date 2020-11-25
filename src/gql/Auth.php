<?php

namespace jamesedmonston\graphqlauthentication\gql;

use craft\gql\GqlEntityRegistry;
use craft\gql\types\generators\UserType;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;

class Auth extends ObjectType
{
    /**
     * @return string
     */
    public static function getName(): string
    {
        return 'Auth';
    }

    /**
     * @return Type
     */
    public static function getType(): Type
    {
        if ($type = GqlEntityRegistry::getEntity(static::class)) {
            return $type;
        }

        return GqlEntityRegistry::createEntity(static::class, new ObjectType([
            'name' => 'Auth',
            'fields' => [
                'accessToken' => Type::nonNull(Type::string()),
                'user' => UserType::generateType(User::class),
            ],
        ]));
    }
}

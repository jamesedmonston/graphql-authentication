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
        if ($type = GqlEntityRegistry::getEntity(static::getName())) {
            return $type;
        }

        return GqlEntityRegistry::createEntity(static::getName(), new ObjectType([
            'name' => static::getName(),
            'fields' => [
                'user' => UserType::generateType(User::class),
                'schema' => Type::nonNull(Type::string()),
                'jwt' => Type::nonNull(Type::string()),
                'jwtExpiresAt' => Type::nonNull(Type::float()),
                'refreshToken' => Type::nonNull(Type::string()),
                'refreshTokenExpiresAt' => Type::nonNull(Type::float()),
            ],
        ]));
    }
}

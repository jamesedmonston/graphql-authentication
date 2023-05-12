<?php

namespace jamesedmonston\graphqlauthentication\gql;

use craft\gql\GqlEntityRegistry;
use craft\gql\interfaces\elements\User;
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
                'user' => Type::getNullableType(User::getType()),
                'schema' => Type::string(),
                'jwt' => Type::string(),
                'jwtExpiresAt' => Type::float(),
                'refreshToken' => Type::string(),
                'refreshTokenExpiresAt' => Type::float(),
                'requiresTwoFactor' => Type::boolean(),
            ],
        ]));
    }
}

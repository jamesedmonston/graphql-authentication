<?php

namespace jamesedmonston\graphqlauthentication\gql;

use craft\gql\GqlEntityRegistry;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;

class JWT extends ObjectType
{
    /**
     * @return string
     */
    public static function getName(): string
    {
        return 'JWT';
    }

    /**
     * @return Type
     */
    public static function getType(): Type
    {
        if ($type = GqlEntityRegistry::getEntity(static::class)) {
            return $type;
        }

        $fields = [
            'jwt' => Type::nonNull(Type::string()),
            'jwtExpiresAt' => Type::nonNull(Type::float()),
            'refreshToken' => Type::nonNull(Type::string()),
            'refreshTokenExpiresAt' => Type::nonNull(Type::float()),
        ];

        return GqlEntityRegistry::createEntity(static::class, new ObjectType([
            'name' => static::getName(),
            'fields' => $fields,
        ]));
    }
}

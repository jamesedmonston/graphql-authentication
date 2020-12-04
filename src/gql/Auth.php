<?php

namespace jamesedmonston\graphqlauthentication\gql;

use craft\gql\GqlEntityRegistry;
use craft\gql\types\generators\UserType;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

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

        $settings = GraphqlAuthentication::$plugin->getSettings();

        $fields = [
            'user' => UserType::generateType(User::class),
            'schema' => Type::nonNull(Type::string()),
        ];

        if ($settings->tokenType !== 'jwt') {
            $fields['accessToken'] = Type::nonNull(Type::string());
        } else {
            $fields['jwt'] = Type::nonNull(Type::string());
            $fields['jwtExpiresAt'] = Type::nonNull(Type::int());
            $fields['refreshToken'] = Type::nonNull(Type::string());
            $fields['refreshTokenExpiresAt'] = Type::nonNull(Type::int());
        }

        return GqlEntityRegistry::createEntity(static::getName(), new ObjectType([
            'name' => static::getName(),
            'fields' => $fields,
        ]));
    }
}

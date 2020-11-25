<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\models\GqlToken;
use DateTime;
use GraphQL\Error\Error;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\InvalidArgumentException;
use yii\web\BadRequestHttpException;

class TokenService extends Component
{
    public static $INVALID_HEADER = 'Invalid Authorization Header';

    // Public Methods
    // =========================================================================

    public function getHeaderToken(): GqlToken
    {
        if (GraphqlAuthentication::$plugin->getSettings()->setCookie && isset($_COOKIE['gql_accessToken'])) {
            try {
                $token = Craft::$app->getGql()->getTokenByAccessToken($_COOKIE['gql_accessToken']);
            } catch (InvalidArgumentException $e) {
                throw new InvalidArgumentException($e);
            }

            if (!isset($token)) {
                throw new BadRequestHttpException(self::$INVALID_HEADER);
            }

            $this->_validateExpiry($token);
            return $token;
        }

        $request = Craft::$app->getRequest();
        $requestHeaders = $request->getHeaders();

        foreach ($requestHeaders->get('authorization', [], false) as $authHeader) {
            $authValues = array_map('trim', explode(',', $authHeader));

            foreach ($authValues as $authValue) {
                if (preg_match('/^Bearer\s+(.+)$/i', $authValue, $matches)) {
                    try {
                        $token = Craft::$app->getGql()->getTokenByAccessToken($matches[1]);
                    } catch (InvalidArgumentException $e) {
                        throw new InvalidArgumentException($e);
                    }

                    if (!$token) {
                        throw new BadRequestHttpException(self::$INVALID_HEADER);
                    }

                    break 2;
                }
            }
        }

        if (!isset($token)) {
            throw new BadRequestHttpException(self::$INVALID_HEADER);
        }

        $this->_validateExpiry($token);
        return $token;
    }

    public function getUserFromToken(): User
    {
        return Craft::$app->getUsers()->getUserById($this->_extractUserId($this->getHeaderToken()));
    }

    public function create(User $user, Int $schemaId): string
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $accessToken = Craft::$app->getSecurity()->generateRandomString(32);
        $time = microtime(true);

        $fields = [
            'name' => "user-{$user->id}-{$time}",
            'accessToken' => $accessToken,
            'enabled' => true,
            'schemaId' => $schemaId,
        ];

        if ($settings->expiration) {
            $fields['expiryDate'] = (new DateTime())->modify("+ {$settings->expiration}");
        }

        $token = new GqlToken($fields);

        if (!Craft::$app->getGql()->saveToken($token)) {
            throw new Error(json_encode($token->getErrors()));
        }

        if ($settings->setCookie) {
            $this->_setTokenCookie($accessToken);
        }

        return $accessToken;
    }

    // Protected Methods
    // =========================================================================

    protected function _setTokenCookie(string $token): bool
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $expiry = 0;

        if ($settings->expiration) {
            $expiry = strtotime((new DateTime())->modify("+ {$settings->expiration}")->format('Y-m-d H:i'));
        }

        if (PHP_VERSION_ID < 70300) {
            return setcookie('gql_accessToken', $token, $expiry, "/; samesite={$settings->sameSitePolicy}", '', true, true);
        }

        return setcookie('gql_accessToken', $token, [
            'expires' => $expiry,
            'path' => '/',
            'domain' => '',
            'secure' => true,
            'httponly' => true,
            'samesite' => $settings->sameSitePolicy,
        ]);
    }

    protected function _extractUserId(GqlToken $token): string
    {
        return explode('-', $token->name)[1];
    }

    protected function _validateExpiry(GqlToken $token)
    {
        if (!$token->expiryDate) {
            return;
        }

        if (strtotime(date('y-m-d H:i:s')) < strtotime($token->expiryDate->format('y-m-d H:i:s'))) {
            return;
        }

        throw new BadRequestHttpException(self::$INVALID_HEADER);
    }
}

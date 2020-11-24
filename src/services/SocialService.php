<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\elements\User;
use craft\gql\GqlEntityRegistry;
use craft\gql\types\generators\UserType;
use craft\services\Gql;
use Google_Client;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\ObjectType;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class SocialService extends Component
{
    public static $CLIENT_NOT_FOUND = 'No Google Client ID exists';
    public static $INVALID_TOKEN = 'Invalid Token ID';
    public static $EMAIL_NOT_FOUND = 'No email in scope';
    public static $EMAIL_MISMATCH = "Email address doesn't match allowed Google domains";

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
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    public function registerGqlMutations(Event $event)
    {
        $users = Craft::$app->getUsers();
        $settings = GraphqlAuthentication::$plugin->getSettings();

        $tokenAndUserType = Type::nonNull(
            GqlEntityRegistry::createEntity('SocialAuth', new ObjectType([
                'name' => 'SocialAuth',
                'fields' => [
                    'accessToken' => Type::nonNull(Type::string()),
                    'user' => UserType::generateType(User::class),
                ],
            ]))
        );

        $event->mutations['googleSignIn'] = [
            'description' => 'Authenticates a user using a Google Sign-In ID token. Returns user and token.',
            'type' => $tokenAndUserType,
            'args' => [
                'idToken' => Type::nonNull(Type::string()),
            ],
            'resolve' => function ($source, array $arguments) use ($users, $settings) {
                if (!$settings->googleClientId) {
                    throw new Error(self::$CLIENT_NOT_FOUND);
                }

                $client = new Google_Client(['client_id' => $settings->googleClientId]);
                $payload = $client->verifyIdToken($arguments['idToken']);

                if (!$payload) {
                    throw new Error(self::$INVALID_TOKEN);
                }

                $email = $payload['email'];

                if (!$email || !isset($email)) {
                    throw new Error(self::$EMAIL_NOT_FOUND);
                }

                if ($settings->allowedGoogleDomains) {
                    $domains = explode(',', str_replace(['http://', 'https://', 'www.', ' ', '/'], '', $settings->allowedGoogleDomains));
                    $hd = $payload['hd'];

                    if (!in_array($hd, $domains)) {
                        throw new Error(self::$EMAIL_MISMATCH);
                    }
                }

                $user = $users->getUserByUsernameOrEmail($email);

                if (!$user) {
                    $firstName = $payload['given_name'];
                    $lastName = $payload['family_name'];

                    $user = GraphqlAuthentication::$plugin->getInstance()->user->create([
                        'email' => $email,
                        'password' => '',
                        'firstName' => $firstName,
                        'lastName' => $lastName,
                    ]);
                }

                $token = GraphqlAuthentication::$plugin->getInstance()->token->create($user);

                return [
                    'accessToken' => $token,
                    'user' => $user,
                ];
            },
        ];
    }
}

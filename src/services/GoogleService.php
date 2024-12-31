<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterGqlMutationsEvent;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Gql;
use Google_Client;
use GraphQL\Error\Error;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class GoogleService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * @inheritdoc
     */
    public function init(): void
    {
        parent::init();

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    /**
     * Registers Google Sign-In mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        if (!GraphqlAuthentication::$tokenService->getHeaderToken()) {
            return;
        }

        if (!$this->_validateSettings()) {
            return;
        }

        switch (GraphqlAuthentication::$settings->permissionType) {
            case 'single':
                $event->mutations['googleSignIn'] = [
                    'description' => 'Authenticates a user using a Google Sign-In ID token. Returns user and token.',
                    'type' => Type::nonNull(Auth::getType()),
                    'args' => [
                        'idToken' => Type::nonNull(Type::string()),
                    ],
                    'resolve' => function($source, array $arguments) {
                        $settings = GraphqlAuthentication::$settings;
                        $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                        if (!$schemaId) {
                            GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                        }

                        $idToken = $arguments['idToken'];
                        $tokenUser = $this->_getUserFromToken($idToken);

                        $user = GraphqlAuthentication::$socialService->authenticate($tokenUser, $schemaId);
                        return $user;
                    },
                ];
                break;

            case 'multiple':
                $userGroupsService = Craft::$app->getUserGroups();
                $userGroups = $userGroupsService->getAllGroups();

                foreach ($userGroups as $userGroup) {
                    $handle = ucfirst($userGroup->handle);

                    $event->mutations["googleSignIn{$handle}"] = [
                        'description' => "Authenticates a {$userGroup->name} using a Google Sign-In ID token. Returns user and token.",
                        'type' => Type::nonNull(Auth::getType()),
                        'args' => [
                            'idToken' => Type::nonNull(Type::string()),
                        ],
                        'resolve' => function($source, array $arguments) use ($userGroup) {
                            $settings = GraphqlAuthentication::$settings;
                            $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                            $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();

                            if (!$schemaId) {
                                GraphqlAuthentication::$errorService->throw($settings->invalidSchema);
                            }

                            $idToken = $arguments['idToken'];
                            $tokenUser = $this->_getUserFromToken($idToken);

                            $user = GraphqlAuthentication::$socialService->authenticate($tokenUser, $schemaId, $userGroup->id);
                            return $user;
                        },
                    ];
                }
                break;
        }
    }

    // Protected Methods
    // =========================================================================

    /**
     * Ensures settings are set
     *
     * @return bool
     */
    protected function _validateSettings(): bool
    {
        $settings = GraphqlAuthentication::$settings;
        return (bool) $settings->googleClientId;
    }

    /**
     * Gets user details from Google Sign-In token
     *
     * @param string $idToken
     * @return array
     * @throws Error
     */
    protected function _getUserFromToken(string $idToken): array
    {
        $settings = GraphqlAuthentication::$settings;
        $errorService = GraphqlAuthentication::$errorService;

        $client = new Google_Client([
            'client_id' => GraphqlAuthentication::getInstance()->getSettingsData($settings->googleClientId),
        ]);

        $payload = $client->verifyIdToken($idToken);

        if (!$payload) {
            $errorService->throw($settings->googleTokenIdInvalid);
        }

        $email = $payload['email'];

        if (!$email) {
            $errorService->throw($settings->emailNotInScope);
        }

        if ($settings->allowedGoogleDomains) {
            GraphqlAuthentication::$socialService->verifyEmailDomain(
                $email,
                $settings->allowedGoogleDomains,
                $settings->googleEmailMismatch
            );
        }

        $fullName = $payload['name'] ?? '';

        return compact(
            'email',
            'fullName'
        );
    }
}

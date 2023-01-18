<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\events\RegisterEmailMessagesEvent;
use craft\events\RegisterGqlMutationsEvent;
use craft\mail\Mailer;
use craft\records\GqlSchema as GqlSchemaRecord;
use craft\services\Elements;
use craft\services\Gql;
use craft\services\SystemMessages;
use craft\services\Users;
use DateTime;
use GraphQL\Type\Definition\Type;
use jamesedmonston\graphqlauthentication\elements\MagicCode;
use jamesedmonston\graphqlauthentication\gql\Auth;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;
use yii\base\Event;

class MagicService extends Component
{
    public function init(): void
    {
        parent::init();

        Event::on(
            SystemMessages::class,
            SystemMessages::EVENT_REGISTER_MESSAGES,
            [$this, 'registerEmails']
        );

        Event::on(
            Gql::class,
            Gql::EVENT_REGISTER_GQL_MUTATIONS,
            [$this, 'registerGqlMutations']
        );
    }

    /**
     * Registers magic authentication emails
     *
     * @param RegisterEmailMessagesEvent $event
     */
    public function registerEmails(RegisterEmailMessagesEvent $event)
    {
        $settings = GraphqlAuthentication::$settings;

        if ($settings->allowMagicAuthentication) {
            $event->messages[] = [
                'key' => 'magic_link',
                'heading' => 'Magic Link Authentication',
                'subject' => 'Open this link to log in to {{systemName}}',
                'body' => "Hey {{user.friendlyName|e}},\r\n\r\nUse the following link to sign in to your account: {{siteUrl}}auth?magicCode={{code}}",
            ];
        }
    }

    /**
     * Registers magic authentication mutations
     *
     * @param RegisterGqlMutationsEvent $event
     */
    public function registerGqlMutations(RegisterGqlMutationsEvent $event)
    {
        $settings = GraphqlAuthentication::$settings;
        $userService = GraphqlAuthentication::$userService;
        $tokenService = GraphqlAuthentication::$tokenService;
        $errorService = GraphqlAuthentication::$errorService;

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        /** @var Users */
        $usersService = Craft::$app->getUsers();

        /** @var Mailer */
        $mailerService = Craft::$app->getMailer();

        if ($settings->allowMagicAuthentication) {
            $event->mutations['sendMagicLink'] = [
                'description' => 'Sends magic log in link. Returns string.',
                'type' => Type::nonNull(Type::string()),
                'args' => [
                    'email' => Type::nonNull(Type::string()),
                ],
                'resolve' => function ($source, array $arguments) use ($settings, $elementsService, $usersService, $mailerService, $errorService) {
                    $email = $arguments['email'];
                    $user = $usersService->getUserByUsernameOrEmail($email);
                    $message = $settings->magicLinkSent;

                    if (!$user) {
                        return $message;
                    }

                    $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $settings->schemaName])->scalar();

                    if ($settings->permissionType === 'multiple') {
                        $userGroup = $user->getGroups()[0] ?? null;

                        if ($userGroup) {
                            $schemaName = $settings->granularSchemas['group-' . $userGroup->id]['schemaName'] ?? null;
                            $schemaId = GqlSchemaRecord::find()->select(['id'])->where(['name' => $schemaName])->scalar();
                        }
                    }

                    if (!$schemaId) {
                        $errorService->throw($settings->invalidSchema);
                    }

                    $code = str_pad(mt_rand(0, 999999), 6, 0, STR_PAD_LEFT);

                    $magicCodeElement = new MagicCode([
                        'code' => $code,
                        'userId' => $user->id,
                        'schemaId' => $schemaId,
                        'expiryDate' => (new DateTime())->modify('+15 mins')->format('Y-m-d H:i:s'),
                    ]);

                    if (!$elementsService->saveElement($magicCodeElement)) {
                        $errors = $magicCodeElement->getErrors();
                        $errorService->throw($errors[key($errors)][0]);
                    }

                    $mailerService
                        ->composeFromKey('magic_link', [
                            'code' => $code,
                            'user' => $user,
                        ])
                        ->setTo($user)
                        ->send();

                    return $message;
                },
            ];

            $event->mutations['verifyMagicCode'] = [
                'description' => 'Verifies magic log in link code. Returns user and token.',
                'type' => Type::nonNull(Auth::getType()),
                'args' => [
                    'code' => Type::nonNull(Type::int()),
                    'email' => Type::nonNull(Type::string()),
                ],
                'resolve' => function ($source, array $arguments) use ($settings, $tokenService, $userService, $elementsService, $usersService, $errorService) {
                    $code = $arguments['code'];
                    $email = $arguments['email'];

                    $this->_clearExpiredCodes();
                    /** @var MagicCode|null $magicCodeElement */
                    $magicCodeElement = MagicCode::find()->where(['[[code]]' => $code])->one();

                    if (!$magicCodeElement) {
                        $errorService->throw($settings->invalidMagicCode);
                    }

                    $user = $usersService->getUserByUsernameOrEmail($email);

                    if (!$user) {
                        $errorService->throw($settings->userNotFound);
                    }

                    if ($user->id !== $magicCodeElement->userId) {
                        $errorService->throw($settings->invalidMagicCode);
                    }

                    $schemaId = $magicCodeElement->schemaId;

                    if (!$schemaId) {
                        $errorService->throw($settings->invalidSchema);
                    }

                    $elementsService->deleteElementById($magicCodeElement->id);
                    $token = $tokenService->create($user, $schemaId);

                    return $userService->getResponseFields($user, $schemaId, $token);
                },
            ];
        }
    }

    /**
     * Clears expired magic codes
     */
    protected function _clearExpiredCodes()
    {
        $magicCodes = MagicCode::find()->where('[[expiryDate]] <= CURRENT_TIMESTAMP')->all();

        /** @var Elements */
        $elementsService = Craft::$app->getElements();

        foreach ($magicCodes as $magicCode) {
            $elementsService->deleteElementById($magicCode->id, null, null, true);
        }
    }
}

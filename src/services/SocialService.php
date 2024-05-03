<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\helpers\StringHelper;
use craft\services\Users;
use GraphQL\Error\Error;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

class SocialService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Verifies emails against allowed domains
     *
     * @param string $email
     * @param string $domains
     * @param string $error
     * @return bool
     * @throws Error
     */
    public function verifyEmailDomain(string $email, string $domains, string $error): bool
    {
        $errorService = GraphqlAuthentication::$errorService;

        if (!StringHelper::contains($email, '@')) {
            $errorService->throw(GraphqlAuthentication::$settings->invalidEmailAddress);
        }

        $domain = explode('@', $email)[1];
        $domains = explode(',', str_replace(['http://', 'https://', 'www.', ' ', '/'], '', $domains));

        if (!in_array($domain, $domains)) {
            $errorService->throw($error);
        }

        return true;
    }

    /**
     * Authenticates a user through social sign-in
     *
     * @param array $tokenUser
     * @param int $schemaId
     * @param int $userGroupId
     * @return array
     * @throws Error
     */
    public function authenticate(array $tokenUser, int $schemaId, int $userGroupId = null): array
    {
        $settings = GraphqlAuthentication::$settings;
        $userService = GraphqlAuthentication::$userService;
        $errorService = GraphqlAuthentication::$errorService;

        $usersService = Craft::$app->getUsers();
        $user = $usersService->getUserByUsernameOrEmail($tokenUser['email']);

        if (!$user) {
            if (!$userGroupId && !$settings->allowRegistration) {
                $errorService->throw($settings->userNotFound);
            }

            if ($userGroupId && !($settings->granularSchemas["group-{$userGroupId}"]['allowRegistration'] ?? false)) {
                $errorService->throw($settings->userNotFound);
            }

            $user = $userService->create([
                'email' => $tokenUser['email'],
                'password' => '',
                'fullName' => $tokenUser['fullName'],
            ], $userGroupId ?? $settings->userGroup, true);
        }

        if ($userGroupId) {
            $assignedGroups = array_column($user->groups, 'id');

            if (!in_array($userGroupId, $assignedGroups)) {
                $errorService->throw($settings->forbiddenMutation);
            }
        }

        $token = GraphqlAuthentication::$tokenService->create($user, $schemaId);
        return $userService->getResponseFields($user, $schemaId, $token);
    }
}

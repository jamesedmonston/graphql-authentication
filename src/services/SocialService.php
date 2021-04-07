<?php

namespace jamesedmonston\graphqlauthentication\services;

use Craft;
use craft\base\Component;
use craft\helpers\StringHelper;
use jamesedmonston\graphqlauthentication\GraphqlAuthentication;

class SocialService extends Component
{
    // Public Methods
    // =========================================================================

    public function verifyEmailDomain(string $email, string $domains, string $error): bool
    {
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;

        if (!StringHelper::contains($email, '@')) {
            $errorService->throw($settings->invalidEmailAddress, 'INVALID');
        }

        $domain = explode('@', $email)[1];
        $domains = explode(',', str_replace(['http://', 'https://', 'www.', ' ', '/'], '', $domains));

        if (!in_array($domain, $domains)) {
            $errorService->throw($error, 'INVALID');
        }

        return true;
    }

    public function authenticate(array $tokenUser, int $schemaId, int $userGroupId = null): array
    {
        $users = Craft::$app->getUsers();
        $settings = GraphqlAuthentication::$plugin->getSettings();
        $userService = GraphqlAuthentication::$plugin->getInstance()->user;
        $tokenService = GraphqlAuthentication::$plugin->getInstance()->token;
        $errorService = GraphqlAuthentication::$plugin->getInstance()->error;

        $user = $users->getUserByUsernameOrEmail($tokenUser['email']);

        if (!$user) {
            if (!$userGroupId && !$settings->allowRegistration) {
                $errorService->throw($settings->userNotFound, 'INVALID');
            }

            if ($userGroupId && !($settings->granularSchemas["group-{$userGroupId}"]['allowRegistration'] ?? false)) {
                $errorService->throw($settings->userNotFound, 'INVALID');
            }

            $user = $userService->create([
                'email' => $tokenUser['email'],
                'password' => '',
                'firstName' => $tokenUser['firstName'],
                'lastName' => $tokenUser['lastName'],
            ], $userGroupId ?? $settings->userGroup);
        }

        if ($userGroupId) {
            $assignedGroups = array_column($user->groups, 'id');

            if (!in_array($userGroupId, $assignedGroups)) {
                $errorService->throw($settings->forbiddenMutation, 'FORBIDDEN');
            }
        }

        $token = $tokenService->create($user, $schemaId);
        return $userService->getResponseFields($user, $schemaId, $token);
    }
}

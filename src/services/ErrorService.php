<?php

namespace jamesedmonston\graphqlauthentication\services;

use craft\base\Component;
use GraphQL\Error\Error;
use yii\base\InvalidValueException;

class ErrorService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Throws GraphQL errors
     *
     * @param string $message
     * @param bool $invalid
     * @throws InvalidValueException
     * @throws Error
     */
    function throw (string $message, bool $invalid = false) {
        if ($invalid) {
            throw new InvalidValueException($message);
        }

        throw new Error($message, null, null, [], null, null, ['code' => 'INVALID']);
    }
}

<?php

namespace jamesedmonston\graphqlauthentication\services;

use craft\base\Component;
use GraphQL\Error\Error;

class ErrorService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Throws GraphQL errors
     *
     * @param string $message
     * @param string $code
     * @throws Error
     */
    function throw (string $message, string $code): Error {
        throw new Error($message, null, null, [], null, null, ['code' => $code]);
    }
}

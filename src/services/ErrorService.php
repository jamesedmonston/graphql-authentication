<?php

namespace jamesedmonston\graphqlauthentication\services;

use craft\base\Component;
use GraphQL\Error\Error;

class ErrorService extends Component
{
    // Public Methods
    // =========================================================================

    function throw (string $message, string $code): Error {
        throw new Error($message, null, null, null, null, null, ['code' => $code]);
    }
}

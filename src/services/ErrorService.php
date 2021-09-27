<?php

namespace jamesedmonston\graphqlauthentication\services;

use craft\base\Component;
use yii\base\InvalidValueException;

class ErrorService extends Component
{
    // Public Methods
    // =========================================================================

    /**
     * Throws GraphQL errors
     *
     * @param string $message
     * @param string $code
     * @throws InvalidValueException
     */
    function throw (string $message): InvalidValueException {
        throw new InvalidValueException($message);
    }
}

<?php

namespace jamesedmonston\graphqlauthentication\events;

use Lcobucci\JWT\Configuration;
use yii\base\Event;

class JwtValidateEvent extends Event
{
    /**
     * @var Configuration The JWT configuration
     */
    public $config;
}

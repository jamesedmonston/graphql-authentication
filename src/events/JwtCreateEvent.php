<?php

namespace jamesedmonston\graphqlauthentication\events;

use craft\elements\User;
use Lcobucci\JWT\Builder;
use yii\base\Event;

class JwtCreateEvent extends Event
{
    /**
     * @var Builder The JWT builder
     */
    public $builder;

    /**
     * @var User The user for which the JWT is being created
     */
    public $user;
}

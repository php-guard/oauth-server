<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 02/06/2018
 * Time: 17:53
 */

namespace OAuth2\Tests\Roles;


use OAuth2\Roles\ResourceOwnerInterface;

class ResourceOwner implements ResourceOwnerInterface
{

    public function getIdentifier(): string
    {
        return 'phpunit';
    }
}
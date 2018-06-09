<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:25
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Roles\ResourceOwnerInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;
use OAuth2\Tests\Roles\ResourceOwner;

class ResourceOwnerStorage implements ResourceOwnerStorageInterface
{
    public function validateCredentials(ResourceOwnerInterface $resourceOwner, string $password): bool
    {
        return $resourceOwner->getIdentifier() == 'phpunit' && $password == 'password';
    }

    /**
     * @param string $identifier
     * @return bool
     */
    public function exists(string $identifier): bool
    {
        return $identifier == 'phpunit';
    }

    public function get(string $identifier): ?ResourceOwnerInterface
    {
        return $identifier == 'phpunit' ? new ResourceOwner() : null;
    }
}
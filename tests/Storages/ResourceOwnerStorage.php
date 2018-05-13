<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:25
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Storages\ResourceOwnerStorageInterface;

class ResourceOwnerStorage implements ResourceOwnerStorageInterface
{
    public function validateCredentials(string $username, string $password): ?string
    {
        return $username == 'phpunit' && $password == 'password' ? $username : null;
    }

    /**
     * @param string $identifier
     * @return bool
     */
    function exists(string $identifier): bool
    {
        return $identifier == 'phpunit';
    }
}
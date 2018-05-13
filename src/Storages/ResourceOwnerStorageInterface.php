<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:21
 */

namespace OAuth2\Storages;


interface ResourceOwnerStorageInterface
{
    function validateCredentials(string $username, string $password): ?string;

    /**
     * @param string $identifier
     * @return bool
     */
    function exists(string $identifier): bool;
}
<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:21
 */

namespace OAuth2\Storages;


use OAuth2\Roles\ResourceOwnerInterface;

interface ResourceOwnerStorageInterface
{
    /**
     * @param ResourceOwnerInterface $resourceOwner
     * @param string $password
     * @return null|ResourceOwnerInterface
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.3
     * The authorization server MUST protect the endpoint against
     * brute force attacks (e.g., using rate-limitation or generating
     * alerts).
     *
     * It's up to you to implement this protection
     * and raise an OAuthException when an attack is detected.
     */
    public function validateCredentials(ResourceOwnerInterface $resourceOwner, string $password): bool;

    /**
     * @param string $identifier
     * @return bool
     */
    public function exists(string $identifier): bool;

    public function get(string $identifier): ?ResourceOwnerInterface;
}
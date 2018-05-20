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
    /**
     * @param string $username
     * @param string $password
     * @return null|string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.3
     * The authorization server MUST protect the endpoint against
     * brute force attacks (e.g., using rate-limitation or generating
     * alerts).
     *
     * It's up to you to implement this protection
     * and raise an OAuthException when an attack is detected.
     */
    function validateCredentials(string $username, string $password): ?string;

    /**
     * @param string $identifier
     * @return bool
     */
    function exists(string $identifier): bool;
}
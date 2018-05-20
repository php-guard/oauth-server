<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:25
 */

namespace OAuth2\Storages;


use OAuth2\Credentials\AccessTokenInterface;
use OAuth2\Credentials\TokenInterface;

interface AccessTokenStorageInterface extends TokenStorageInterface
{
    /**
     * @param string $token
     * @return null|AccessTokenInterface
     */
    function get(string $token): ?TokenInterface;

    /**
     * @param array $scopes
     * @param string $clientIdentifier
     * @param null|string $resourceOwnerIdentifier
     * @param null|string $authorizationCode
     * @return AccessTokenInterface
     */
    function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null,
                      ?string $authorizationCode = null): TokenInterface;
}
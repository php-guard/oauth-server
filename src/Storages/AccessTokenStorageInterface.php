<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:25
 */

namespace OAuth2\Storages;


use OAuth2\Credentials\AccessTokenInterface;

interface AccessTokenStorageInterface
{
    function get(string $token): ?AccessTokenInterface;

    function revoke(string $token);

    function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null,
                      ?string $authorizationCode = null): AccessTokenInterface;

    function getLifetime(): ?int;

    /**
     * @param string $code
     * @return AccessTokenInterface[]|null
     */
    function getByAuthorizationCode(string $code): ?array;

    function hasExpired(AccessTokenInterface $accessToken): bool;

    function getSize(): ?int;
}
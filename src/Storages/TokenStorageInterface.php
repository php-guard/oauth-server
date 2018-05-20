<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 19/05/2018
 * Time: 16:16
 */

namespace OAuth2\Storages;


use OAuth2\Credentials\TokenInterface;

interface TokenStorageInterface
{
    function get(string $token): ?TokenInterface;

    function revoke(string $token);

    function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null,
                      ?string $authorizationCode = null): TokenInterface;

    function getLifetime(): ?int;

    /**
     * @param string $code
     * @return TokenInterface[]|null
     */
    function getByAuthorizationCode(string $code): array;

    function hasExpired(TokenInterface $accessToken): bool;

    function getSize(): ?int;
}
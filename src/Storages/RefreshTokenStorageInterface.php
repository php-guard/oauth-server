<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:25
 */

namespace OAuth2\Storages;

use OAuth2\Credentials\RefreshTokenInterface;

interface RefreshTokenStorageInterface
{
    function get(string $token): ?RefreshTokenInterface;

    function revoke(string $token);

    function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null): RefreshTokenInterface;

    function getLifetime(): ?int;

    function hasExpired(RefreshTokenInterface $refreshToken): bool;
}
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
public function get(string $token): ?TokenInterface;

public function revoke(string $token);

public function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null,
                      ?string $authorizationCode = null): TokenInterface;

public function getLifetime(): ?int;

    /**
     * @param string $code
     * @return TokenInterface[]|null
     */
public function getByAuthorizationCode(string $code): array;

public function hasExpired(TokenInterface $accessToken): bool;

public function getSize(): ?int;
}
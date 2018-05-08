<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 19:47
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Credentials\RefreshToken;
use OAuth2\Credentials\RefreshTokenInterface;
use OAuth2\Helper;
use OAuth2\Storages\RefreshTokenStorageInterface;

class RefreshTokenStorage implements RefreshTokenStorageInterface
{
    protected $tokens = [];

    function get(string $token): ?RefreshTokenInterface
    {
        return $this->tokens[$token] ?? null;
    }

    function revoke(string $token)
    {
        unset($this->tokens[$token]);
    }

    function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null): RefreshTokenInterface
    {
        $expiresAt = new \DateTime('now', new \DateTimeZone('UTC'));
        $expiresAt->modify('+'.$this->getLifetime().' seconds');

        $refreshToken = new RefreshToken(Helper::generateToken(20), $scopes, $clientIdentifier, $resourceOwnerIdentifier,
            $expiresAt);
        $this->tokens[$refreshToken->getToken()] = $refreshToken;
        return $refreshToken;
    }

    function hasExpired(RefreshTokenInterface $refreshToken): bool
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        return $now > $refreshToken->getExpiresAt();
    }

    function getLifetime(): ?int
    {
        return 3600 * 24 * 7;
    }
}
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
use OAuth2\Credentials\TokenInterface;
use OAuth2\Helper;
use OAuth2\Storages\RefreshTokenStorageInterface;

class RefreshTokenStorage implements RefreshTokenStorageInterface
{
    /**
     * @var RefreshToken[]
     */
    protected $tokens = [];

public function get(string $token): ?TokenInterface
    {
        return $this->tokens[$token] ?? null;
    }

public function revoke(string $token)
    {
        unset($this->tokens[$token]);
    }

    /**
     * @param array $scopes
     * @param string $clientIdentifier
     * @param null|string $resourceOwnerIdentifier
     * @param null|string $authorizationCode
     * @return RefreshTokenInterface
     * @throws \Exception
     */
public function generate(array $scopes, string $clientIdentifier,
                      ?string $resourceOwnerIdentifier = null, ?string $authorizationCode = null): TokenInterface
    {
        $expiresAt = new \DateTime('now', new \DateTimeZone('UTC'));
        $expiresAt->modify('+'.$this->getLifetime().' seconds');

        $refreshToken = new RefreshToken(Helper::generateToken(20), $scopes, $clientIdentifier, $resourceOwnerIdentifier,
            $expiresAt, $authorizationCode);
        $this->tokens[$refreshToken->getToken()] = $refreshToken;
        return $refreshToken;
    }

public function hasExpired(TokenInterface $refreshToken): bool
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        return $now > $refreshToken->getExpiresAt();
    }

public function getLifetime(): ?int
    {
        return 3600 * 24 * 7;
    }

    /**
     * @param string $code
     * @return TokenInterface[]|null
     */
public function getByAuthorizationCode(string $code): array
    {
        $tokens = [];
        foreach ($this->tokens as $token) {
            if ($token->getAuthorizationCode() === $code) {
                $tokens[] = $token;
            }
        }
        return $tokens;
    }

public function getSize(): ?int
    {
        return 20;
    }
}
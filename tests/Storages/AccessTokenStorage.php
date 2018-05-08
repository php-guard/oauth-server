<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 19:35
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Credentials\AccessToken;
use OAuth2\Credentials\AccessTokenInterface;
use OAuth2\Credentials\Token;
use OAuth2\Helper;
use OAuth2\Storages\AccessTokenStorageInterface;

class AccessTokenStorage implements AccessTokenStorageInterface
{
    /**
     * @var AccessTokenInterface[]
     */
    protected $tokens = [];

    public function get(string $token): ?AccessTokenInterface
    {
        return $this->tokens[$token] ?? null;
    }

    public function revoke(string $token)
    {
        unset($this->tokens[$token]);
    }

    public function generate(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null,
                             ?string $authorizationCode = null): AccessTokenInterface
    {
        $expiresAt = new \DateTime('now', new \DateTimeZone('UTC'));
        $expiresAt->modify('+'.$this->getLifetime().' seconds');
        $accessToken = new AccessToken(Helper::generateToken(20), 'bearer', $scopes, $clientIdentifier,
            $resourceOwnerIdentifier, $expiresAt, $authorizationCode);
        $this->tokens[$accessToken->getToken()] = $accessToken;
        return $accessToken;
    }

    public function getLifetime(): ?int
    {
        return 1800;
    }

    /**
     * @param string $code
     * @return AccessTokenInterface[]|null
     */
    public function getByAuthorizationCode(string $code): ?array
    {
        $tokens = [];
        foreach ($this->tokens as $token) {
            if ($token instanceof AccessToken && $token->getAuthorizationCode() === $code) {
                $tokens[] = $token;
            }
        }
        return $tokens;
    }

    public function hasExpired(AccessTokenInterface $accessToken): bool
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        return $now > $accessToken->getExpiresAt();
    }

    public function getSize(): ?int
    {
        return 20;
    }
}
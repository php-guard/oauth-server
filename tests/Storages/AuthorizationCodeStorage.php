<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 19:10
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Storages\AuthorizationCodeStorageInterface;
use \OAuth2\Extensions\PKCE\Credentials\AuthorizationCode;
use OAuth2\Credentials\AuthorizationCodeInterface;
use OAuth2\Extensions\PKCE\Credentials\CodeChallenge;
use OAuth2\Extensions\PKCE\Credentials\CodeChallengeInterface;
use OAuth2\Helper;

class AuthorizationCodeStorage implements AuthorizationCodeStorageInterface,
    \OAuth2\Extensions\PKCE\Storages\AuthorizationCodeStorageInterface
{
    protected $codes = [];

    public function get(string $code): ?AuthorizationCodeInterface
    {
        return $this->codes[$code] ?? null;
    }

    public function revoke(string $code): void
    {
        unset($this->codes[$code]);
    }

    /**
     * @param array $scopes
     * @param string $clientIdentifier
     * @param string $resourceOwnerIdentifier
     * @param array|null $requestedScopes
     * @param null|string $redirectUri
     * @return AuthorizationCodeInterface
     * @throws \Exception
     */
    public function generate(array $scopes, string $clientIdentifier, string $resourceOwnerIdentifier,
                             ?array $requestedScopes, ?string $redirectUri): AuthorizationCodeInterface
    {
        $expiresAt = (new \DateTime('now', new \DateTimeZone('UTC')))->modify('+1 minute');
        $authorizationCode = new AuthorizationCode(Helper::generateToken($this->getSize()), $scopes, $clientIdentifier, $resourceOwnerIdentifier,
            $expiresAt, $requestedScopes, $redirectUri);

        $this->codes[$authorizationCode->getCode()] = $authorizationCode;

        return $authorizationCode;
    }

    public function getCodeChallenge(AuthorizationCodeInterface $authorizationCode): ?CodeChallengeInterface
    {
        if ($authorizationCode instanceof AuthorizationCode) {
            return new CodeChallenge($authorizationCode->getCodeChallenge(), $authorizationCode->getCodeChallengeMethod());
        }
        return null;
    }

    public function associate(CodeChallengeInterface $codeChallenge, AuthorizationCodeInterface $authorizationCode)
    {
        if (!$authorizationCode instanceof AuthorizationCode) {
            throw new \InvalidArgumentException();
        }
        $authorizationCode->setCodeChallenge($codeChallenge->getCodeChallenge());
        $authorizationCode->setCodeChallengeMethod($codeChallenge->getCodeChallengeMethod());

        $this->codes[$authorizationCode->getCode()] = $authorizationCode;
    }

    public function hasExpired(AuthorizationCodeInterface $authorizationCode): bool
    {
        $now = new \DateTime('now', new \DateTimeZone('UTC'));
        return $now > $authorizationCode->getExpiresAt();
    }

    public function getSize(): ?int
    {
        return 8;
    }
}
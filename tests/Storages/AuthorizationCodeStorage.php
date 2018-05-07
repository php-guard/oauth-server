<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 19:10
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Extensions\OpenID\Storages\AuthorizationCodeStorageInterface;
use \OAuth2\Extensions\PKCE\Credentials\AuthorizationCode;
use OAuth2\Credentials\AuthorizationCodeInterface;
use OAuth2\Extensions\PKCE\Credentials\CodeChallenge;
use OAuth2\Extensions\PKCE\Credentials\CodeChallengeInterface;
use OAuth2\Helper;

class AuthorizationCodeStorage implements AuthorizationCodeStorageInterface,
    \OAuth2\Extensions\PKCE\Storages\AuthorizationCodeStorageInterface
{
    protected $codes = [];

    public function find(string $code): ?AuthorizationCodeInterface
    {
        return $this->codes[$code] ?? null;
    }

    public function revoke(string $code): void
    {
        unset($this->codes[$code]);
    }

    public function generate(string $scope, string $clientIdentifier, string $resourceOwnerIdentifier,
                             ?string $requestedScope, ?string $redirectUri, ?string $idToken = null): AuthorizationCodeInterface
    {
        $expiresAt = time() + 30;
        $authorizationCode = new AuthorizationCode(Helper::generateToken($this->getSize()), $scope, $clientIdentifier, $resourceOwnerIdentifier,
            $expiresAt, $requestedScope, $redirectUri);

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
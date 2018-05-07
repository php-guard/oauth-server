<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 21:57
 */

namespace OAuth2\Extensions\PKCE\Credentials;


class AuthorizationCode extends \OAuth2\Credentials\AuthorizationCode
{
    /**
     * @var string|null
     */
    protected $codeChallenge;
    /**
     * @var string|null
     */
    protected $codeChallengeMethod;

    public function __construct(string $code, string $scope, string $clientIdentifier, string $resourceOwnerIdentifier,
                                int $expiresAt, ?string $requestedScope = null, ?string $redirectUri = null,
                                ?string $codeChallenge = null, ?string $codeChallengeMethod = null)
    {
       parent::__construct($code, $scope, $clientIdentifier, $resourceOwnerIdentifier, $expiresAt, $requestedScope, $redirectUri);
        $this->codeChallenge = $codeChallenge;
        $this->codeChallengeMethod = $codeChallengeMethod;
    }

    /**
     * @return null|string
     */
    public function getCodeChallenge(): ?string
    {
        return $this->codeChallenge;
    }

    /**
     * @param null|string $codeChallenge
     */
    public function setCodeChallenge(?string $codeChallenge): void
    {
        $this->codeChallenge = $codeChallenge;
    }

    /**
     * @return null|string
     */
    public function getCodeChallengeMethod(): ?string
    {
        return $this->codeChallengeMethod;
    }

    /**
     * @param null|string $codeChallengeMethod
     */
    public function setCodeChallengeMethod(?string $codeChallengeMethod): void
    {
        $this->codeChallengeMethod = $codeChallengeMethod;
    }
}
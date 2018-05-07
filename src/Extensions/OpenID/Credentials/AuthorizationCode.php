<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 17/03/2018
 * Time: 13:50
 */

namespace OAuth2\Extensions\OpenID\Credentials;


class AuthorizationCode extends \OAuth2\Credentials\AuthorizationCode implements AuthorizationCodeInterface
{

    /**
     * @var string|null
     */
    protected $idToken;

    public function __construct(string $code, string $scope, string $clientIdentifier, string $resourceOwnerIdentifier,
                                int $expiresAt, ?string $requestedScope = null, ?string $redirectUri = null,
                                ?string $idToken = null)
    {
        parent::__construct($code, $scope, $clientIdentifier, $resourceOwnerIdentifier,
            $expiresAt, $requestedScope, $redirectUri);
        $this->idToken = $idToken;
    }

    public function getIdToken(): ?string
    {
        return $this->idToken;
    }

    /**
     * @param null|string $idToken
     */
    public function setIdToken(?string $idToken): void
    {
        $this->idToken = $idToken;
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\Extensions\OpenID\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\OpenID\Credentials\AuthorizationCodeInterface;
use OAuth2\Extensions\OpenID\IdTokenManager;
use OAuth2\Flows\FlowInterface;
use OAuth2\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use OAuth2\Tests\Storages\RefreshTokenStorage;

class HybridFlow implements FlowInterface
{

    /**
     * @var AuthorizationCodeStorageInterface
     */
    private $authorizationCodeStorage;
    /**
     * @var AccessTokenStorageInterface
     */
    private $accessTokenStorage;
    /**
     * @var IdTokenManager
     */
    private $idTokenManager;

    public function __construct(AuthorizationCodeStorageInterface $authorizationCodeStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage,
                                IdTokenManager $idTokenManager)
    {
        $this->authorizationCodeStorage = $authorizationCodeStorage;
        $this->accessTokenStorage = $accessTokenStorage;
        $this->idTokenManager = $idTokenManager;
    }

    public function getResponseTypes(): array
    {
        return ['code id_token', 'code token', 'code id_token token'];
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     */
    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
    }

    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        if (!$authorizationEndpoint instanceof \OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint) {
            throw new \InvalidArgumentException();
        }

        $result = [];
        $idTokenClaims = [];
        $responseTypes = explode(' ', $requestData['response_type']);
        if (in_array('code', $responseTypes)) {
//            $resourceOwnerClaims = $authorizationEndpoint->getResourceOwner()->getClaims($authorizationEndpoint->getScopes());
//            $idTokenTokenEndpoint = $this->idTokenManager->issueIdToken(
//                $authorizationEndpoint->getClient(),
//                $authorizationEndpoint->getResourceOwner(),
//                $resourceOwnerClaims
//            );

            $authorizationCode = $this->authorizationCodeStorage->generate(
                $authorizationEndpoint->getScopes(),
                $authorizationEndpoint->getClient()->getIdentifier(),
                $authorizationEndpoint->getResourceOwner()->getIdentifier(),
                $requestData['scope'] ?? null,
                $requestData['redirect_uri'] ?? null
//                $idTokenTokenEndpoint
            );

            if (!$authorizationCode instanceof AuthorizationCodeInterface) {
                throw new \InvalidArgumentException();
            }

            $idTokenClaims['c_hash'] = $this->idTokenManager->getCodeHash(
                $authorizationEndpoint->getClient(), $authorizationCode);
            $result['code'] = $authorizationCode->getCode();
        }

        if (in_array('token', $responseTypes)) {
            $accessToken = $this->accessTokenStorage->generate(
                implode(' ', $authorizationEndpoint->getScopes()),
                $authorizationEndpoint->getClient()->getIdentifier(),
                $authorizationEndpoint->getResourceOwner()->getIdentifier()
            );

            $idTokenClaims['at_hash'] = $this->idTokenManager->getAccessTokenHash(
                $authorizationEndpoint->getClient(), $accessToken);
            $result['access_token'] = $accessToken->getToken();
        }

        if (in_array('id_token', $responseTypes)) {
            $result['id_token'] = $this->idTokenManager->issueIdToken(
                $authorizationEndpoint->getClient(),
                $authorizationEndpoint->getResourceOwner(),
                $idTokenClaims
            );
        }

        return $result;
    }

    public function getDefaultResponseMode(): string
    {
        return 'fragment';
    }

    public function getUnsupportedResponseModes(): array
    {
        return ['query'];
    }

    public function getGrantTypes(): array
    {
        return [];
    }

    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        return [];
    }
}
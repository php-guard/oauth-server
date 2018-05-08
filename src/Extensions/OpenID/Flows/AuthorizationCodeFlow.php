<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/03/2018
 * Time: 17:40
 */

namespace OAuth2\Extensions\OpenID\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\OpenID\IdTokenManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Storages\ClientStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;

class AuthorizationCodeFlow extends \OAuth2\Flows\AuthorizationCodeFlow
{
    /**
     * @var IdTokenManager
     */
    private $idTokenManager;
    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;
    /**
     * @var ResourceOwnerStorageInterface
     */
    private $resourceOwnerStorage;

    public function __construct(AuthorizationCodeStorageInterface $authorizationCodeStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage,
                                ClientStorageInterface $clientStorage,
                                ResourceOwnerStorageInterface $resourceOwnerStorage,
                                IdTokenManager $idTokenManager)
    {
        parent::__construct($authorizationCodeStorage, $accessTokenStorage, $refreshTokenStorage);
        $this->idTokenManager = $idTokenManager;
        $this->clientStorage = $clientStorage;
        $this->resourceOwnerStorage = $resourceOwnerStorage;
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     * @throws OAuthException
     */
    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
        parent::verifyAuthorizationRequest($authorizationEndpoint, $requestData);

        if (in_array('openid', $authorizationEndpoint->getScopes())) {
            if (!$authorizationEndpoint instanceof \OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint) {
                throw new \InvalidArgumentException();
            }
            if (!$authorizationEndpoint->getNonce()) {
                throw new OAuthException('invalid_request', 'Nonce required');
            }

            if (empty($requestData['redirect_uri'])) {
                throw new OAuthException('invalid_request', 'The request is missing the required parameter redirect_uri.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }
        }
    }

//    /**
//     * @param AuthorizationEndpoint $authorizationEndpoint
//     * @param array $requestData
//     * @return array
//     */
//    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
//    {
//        $authorizationCode = $this->createAuthorizationCode($authorizationEndpoint);
//        return ['code' => $authorizationCode->getCode()];
//    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        $tokens = parent::handleAccessTokenRequest($tokenEndpoint, $requestData);

        if (in_array('openid', $this->authorizationCode->getScopes())) {

            $resourceOwnerIdentifier = $this->authorizationCode->getResourceOwnerIdentifier();

            if (!$this->resourceOwnerStorage->exists($resourceOwnerIdentifier)) {
                throw new OAuthException('server_error',
                    'The authorization server encountered an unexpected condition that prevented it from fulfilling 
                    the request. The resource owner of this authorization code is missing.',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }

            $claims = [];

            $idToken = $this->idTokenManager->issueIdToken(
                $this->clientStorage->get($this->authorizationCode->getClientIdentifier()),
                $resourceOwnerIdentifier,
                $claims
            );
            $tokens['id_token'] = $idToken;
        }

        return $tokens;
    }
//
//    protected function createAuthorizationCode(AuthorizationEndpoint $authorizationEndpoint)
//    {
//        return $this->authorizationCodeStorage->generate(
//            implode(' ', $authorizationEndpoint->getScopes()),
//            $authorizationEndpoint->getClient()->getIdentifier(),
//            $authorizationEndpoint->getResourceOwner()->getIdentifier(),
//            $requestData['scope'] ?? null,
//            $requestData['redirect_uri'] ?? null
//        );
//    }

}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 14/03/2018
 * Time: 22:13
 */

namespace OAuth2\Extensions\OpenID\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\OpenID\IdTokenManager;
use OAuth2\Extensions\OpenID\Roles\Clients\ClientMetadataInterface;
use OAuth2\Flows\FlowInterface;
use OAuth2\GrantTypes\AbstractGrantType;
use OAuth2\Helper;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

class ImplicitFlow extends AbstractGrantType implements FlowInterface
{
    /**
     * @var IdTokenManager
     */
    private $idTokenManager;

    public function __construct(AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage,
                                IdTokenManager $idTokenManager)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->idTokenManager = $idTokenManager;
    }

    /**
     * @return string[]
     */
    function getResponseTypes(): array
    {
        return [
            'id_token',
            'id_token token'
        ];
    }

    /**
     * @return string[]
     */
    function getGrantTypes(): array
    {
        return [];
    }

    function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        return [];
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     * @throws OAuthException
     */
    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
        if (!$authorizationEndpoint instanceof \OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint) {
            throw new \InvalidArgumentException();
        }
        if (!$authorizationEndpoint->getNonce()) {
            throw new OAuthException('invalid_request', 'Nonce required');
        }
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     * @return array
     */
    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        if (!$authorizationEndpoint instanceof \OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint) {
            throw new \InvalidArgumentException();
        }

        if (!is_null($authorizationEndpoint->getMaxAge())) {
            $time = $authorizationEndpoint->getResourceOwner()->getLastTimeActivelyAuthenticated();
            $idToken['auth_time'] = $time ? $time->getTimestamp() : $authorizationEndpoint->getMaxAge();
        }

        if (!is_null($authorizationEndpoint->getNonce())) {
            $idToken['nonce'] = $authorizationEndpoint->getNonce();
        }

        $acr = $authorizationEndpoint->getResourceOwner()->getAuthenticationContextClassReference();
        if (!is_null($acr)) {
            $idToken['acr'] = $acr;
        }

        $amr = $authorizationEndpoint->getResourceOwner()->getAuthenticationMethodsReferences();
        if (!is_null($amr)) {
            $idToken['amr'] = $amr;
        }

        $accessToken = $this->issueAccessToken(
            implode(' ', $authorizationEndpoint->getScopes()),
            $authorizationEndpoint->getClient()->getIdentifier(),
            $authorizationEndpoint->getResourceOwner()->getIdentifier()
        );

        $alg = 'RS256';
        $metadata = $authorizationEndpoint->getClient()->getMetadata();
        if ($metadata instanceof ClientMetadataInterface) {
            $alg = $metadata->getIdTokenSignedResponseAlg() ?: 'RS256';
        }

        $macAlgorithm = substr($alg, -3);

        if (!in_array($macAlgorithm, [256, 384, 512])) {
            die("algotihmn not supported");
        }
        $macAlgorithm = 'sha' . $macAlgorithm;


        $atHash = hash($macAlgorithm, $accessToken['access_token'], true);
        $atHash = substr($atHash, 0, strlen($atHash) / 2);
        $atHash = Helper::base64url_encode($atHash);
        $idToken['at_hash'] = $atHash;

        $result = $this->idTokenManager->issueIdToken($authorizationEndpoint->getClient(), $authorizationEndpoint->getResourceOwner());
        $result = array_merge($result, $accessToken);
        return $result;
    }

    function getDefaultResponseMode(): string
    {
        return 'fragment';
    }

    function getUnsupportedResponseModes(): array
    {
        return ['query'];
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 14/03/2018
 * Time: 22:13
 */

namespace OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\Authorization\AuthorizationRequestInterface;
use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\OpenID\IdTokenManager;
use OAuth2\Extensions\OpenID\Roles\Clients\ClientMetadataInterface;
use OAuth2\AuthorizationGrantTypes\Flows\FlowInterface;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;
use OAuth2\Extensions\OpenID\Roles\ResourceOwnerInterface;
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
    public function getResponseTypes(): array
    {
        return [
            'id_token',
            'id_token token'
        ];
    }

    /**
     * @return string[]
     */
    public function getGrantTypes(): array
    {
        return [];
    }

    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
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
    public function handleAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): array
    {
        if (!$authorizationEndpoint instanceof \OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint) {
            throw new \InvalidArgumentException();
        }

        $resourceOwner = $authorizationEndpoint->getResourceOwner();
        $idToken = [];

        if ($resourceOwner instanceof ResourceOwnerInterface) {
            if (!is_null($authorizationEndpoint->getMaxAge())) {
                $time = $resourceOwner->getLastTimeActivelyAuthenticated();
                $idToken['auth_time'] = $time ? $time->getTimestamp() : $authorizationEndpoint->getMaxAge();
            }
            $acr = $resourceOwner->getAuthenticationContextClassReference();
            if (!is_null($acr)) {
                $idToken['acr'] = $acr;
            }

            $amr = $resourceOwner->getAuthenticationMethodsReferences();
            if (!is_null($amr)) {
                $idToken['amr'] = $amr;
            }
        }

        if (!is_null($authorizationEndpoint->getNonce())) {
            $idToken['nonce'] = $authorizationEndpoint->getNonce();
        }

        $accessToken = $this->issueAccessToken(
            $authorizationEndpoint->getScopes(),
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
            throw new \UnexpectedValueException("Algotihmn '".$macAlgorithm."' not supported");
        }
        $macAlgorithm = 'sha' . $macAlgorithm;


        $atHash = hash($macAlgorithm, $accessToken['access_token'], true);
        $atHash = substr($atHash, 0, strlen($atHash) / 2);
        $atHash = Helper::base64url_encode($atHash);
        $idToken['at_hash'] = $atHash;

        $result = [];
        $result['id_token'] = $this->idTokenManager->issueIdToken(
            $authorizationEndpoint->getClient(),
            $authorizationEndpoint->getResourceOwner()
        );

//        $result = array_merge($result, $accessToken);
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

    public function isRegistrationOfRedirectUriRequired(): bool
    {
        return true;
    }
}
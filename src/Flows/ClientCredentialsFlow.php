<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:41
 */

namespace OAuth2\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\GrantTypes\AbstractGrantType;
use OAuth2\Roles\Clients\ConfidentialClientInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

class ClientCredentialsFlow extends AbstractGrantType implements FlowInterface
{
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;

    public function __construct(ScopePolicyManager $scopePolicyManager,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->scopePolicyManager = $scopePolicyManager;
    }

    public function getResponseTypes(): array
    {
        return [];
    }

    public function getGrantTypes(): array
    {
        return ['client_credentials'];
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (!$tokenEndpoint->getClient() instanceof ConfidentialClientInterface) {
            throw new OAuthException('unauthorized_client',
                'The authenticated client is not authorized to use this authorization grant type. 
                The client credentials grant type MUST only be used by confidential clients.',
                'https://tools.ietf.org/html/rfc6749#section-4.4');
        }

        $scopes = $this->scopePolicyManager->getScopes($tokenEndpoint->getClient(), $requestData['scope'] ?? null, $requestedScopes);
        $this->scopePolicyManager->verifyScopes($tokenEndpoint->getClient(), $scopes);

        $responseData = $this->issueAccessToken($scopes, $tokenEndpoint->getClient()->getIdentifier(), null);
        if(is_null($requestedScopes) || array_diff($requestedScopes, $scopes)) {
            $responseData['scope'] = implode(' ', $scopes);
        }

        return $responseData;
    }

    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        throw new \BadMethodCallException();
    }

    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
        throw new \BadMethodCallException();
    }

    public function getDefaultResponseMode(): string
    {
        throw new \BadMethodCallException();
    }

    public function getUnsupportedResponseModes(): array
    {
        throw new \BadMethodCallException();
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:16
 */

namespace OAuth2\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\GrantTypes\AbstractGrantType;
use OAuth2\Roles\Clients\RegisteredClient;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;
use Symfony\Component\VarDumper\VarDumper;

class ResourceOwnerPasswordCredentialsFlow extends AbstractGrantType implements FlowInterface
{
    /**
     * @var ResourceOwnerStorageInterface
     */
    private $resourceOwnerStorage;
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;

    public function __construct(ScopePolicyManager $scopePolicyManager,
                                ResourceOwnerStorageInterface $resourceOwnerStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->resourceOwnerStorage = $resourceOwnerStorage;
        $this->scopePolicyManager = $scopePolicyManager;
    }

    public function getResponseTypes(): array
    {
        return [];
    }

    public function getGrantTypes(): array
    {
        return ['password'];
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (empty($requestData['username'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter username.',
                'https://tools.ietf.org/html/rfc7636#section-4.3');
        }

        if (empty($requestData['password'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter password.',
                'https://tools.ietf.org/html/rfc7636#section-4.3');
        }

        $client = $tokenEndpoint->getClient();

        $scopes = $this->scopePolicyManager->getScopes($client, $requestData['scope'] ?? null, $requestedScopes);
        $this->scopePolicyManager->verifyScopes($client, $scopes);

        $resourceOwnerIdentifier = $this->resourceOwnerStorage->validateCredentials(
            $requestData['username'], $requestData['password']);

        if (is_null($resourceOwnerIdentifier)) {
            throw new OAuthException('invalid_grant',
                'The provider authorization grant is invalid. Resource owner credentials invalid.',
                'https://tools.ietf.org/html/rfc7636#section-4.3');
        }

        $responseData = $this->issueTokens($scopes, $client->getIdentifier(), $resourceOwnerIdentifier);
        if(is_null($requestedScopes) || array_diff($requestedScopes, $scopes)) {
            $responseData['scope'] = implode(' ', $scopes);
        }

        return $responseData;
    }

    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
        throw new \BadMethodCallException();
    }

    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
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
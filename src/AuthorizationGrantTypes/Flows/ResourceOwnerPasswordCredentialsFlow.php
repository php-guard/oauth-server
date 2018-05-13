<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:16
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;
use OAuth2\Helper;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;


/**
 * Class ResourceOwnerPasswordCredentialsFlow
 * @package OAuth2\AuthorizationGrantTypes\Flows
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3.3
 * The resource owner password credentials (i.e., username and password)
 * can be used directly as an authorization grant to obtain an access
 * token.  The credentials should only be used when there is a high
 * degree of trust between the resource owner and the client (e.g., the
 * client is part of the device operating system or a highly privileged
 * application), and when other authorization grant types are not
 * available (such as an authorization code).
 *
 * Even though this grant type requires direct client access to the
 * resource owner credentials, the resource owner credentials are used
 * for a single request and are exchanged for an access token.  This
 * grant type can eliminate the need for the client to store the
 * resource owner credentials for future use, by exchanging the
 * credentials with a long-lived access token or refresh token.
 */
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

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.3
         * The authorization and token endpoints allow the client to specify the
         * scope of the access request using the "scope" request parameter.  In
         * turn, the authorization server uses the "scope" response parameter to
         * inform the client of the scope of the access token issued.
         */
        if (Helper::array_equals($requestedScopes, $scopes)) {
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
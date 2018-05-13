<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:41
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;
use OAuth2\Helper;
use OAuth2\Roles\ClientTypes\ConfidentialClientInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

/**
 * Class ClientCredentialsFlow
 * @package OAuth2\AuthorizationGrantTypes\Flows
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3.4
 * The client credentials (or other forms of client authentication) can
 * be used as an authorization grant when the authorization scope is
 * limited to the protected resources under the control of the client,
 * or to protected resources previously arranged with the authorization
 * server.  Client credentials are used as an authorization grant
 * typically when the client is acting on its own behalf (the client is
 * also the resource owner) or is requesting access to protected
 * resources based on an authorization previously arranged with the
 * authorization server.
 */
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

        $responseData = $this->issueAccessToken($scopes, $tokenEndpoint->getClient()->getIdentifier(), null);

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.3
         * The authorization and token endpoints allow the client to specify the
         * scope of the access request using the "scope" request parameter.  In
         * turn, the authorization server uses the "scope" response parameter to
         * inform the client of the scope of the access token issued.
         */
        if(Helper::array_equals($requestedScopes, $scopes)) {
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
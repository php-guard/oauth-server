<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:41
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\Authorization\AuthorizationRequest;
use OAuth2\Endpoints\Authorization\AuthorizationRequestInterface;
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
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.4
 * The client can request an access token using only its client
 * credentials (or other supported means of authentication) when the
 * client is requesting access to the protected resources under its
 * control, or those of another resource owner that have been previously
 * arranged with the authorization server (the method of which is beyond
 * the scope of this specification).
 *
 * The client credentials grant type MUST only be used by confidential
 * clients.
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

    /**
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.4.1
     * Since the client authentication is used as the authorization grant,
     * no additional authorization request is needed.
     */
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
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.4.2
     * The client makes a request to the token endpoint by adding the
     * following parameters using the "application/x-www-form-urlencoded"
     * format per Appendix B with a character encoding of UTF-8 in the HTTP
     * request entity-body:
     *
     * grant_type
     * REQUIRED.  Value MUST be set to "client_credentials".
     *
     * scope
     * OPTIONAL.  The scope of the access request as described by
     * Section 3.3.
     *
     * The client MUST authenticate with the authorization server as
     * described in Section 3.2.1.
     *
     * For example, the client makes the following HTTP request using
     * transport-layer security (with extra line breaks for display purposes
     * only):
     *
     * POST /token HTTP/1.1
     * Host: server.example.com
     * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
     * Content-Type: application/x-www-form-urlencoded
     *
     * grant_type=client_credentials
     *
     * The authorization server MUST authenticate the client.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.4.3
     * If the access token request is valid and authorized, the
     * authorization server issues an access token as described in
     * Section 5.1.  A refresh token SHOULD NOT be included.  If the request
     * failed client authentication or is invalid, the authorization server
     * returns an error response as described in Section 5.2.
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (!$tokenEndpoint->getClient() instanceof ConfidentialClientInterface) {
            throw new OAuthException('unauthorized_client',
                'The authenticated client is not authorized to use this authorization grant type. 
                The client credentials grant type MUST only be used by confidential clients.',
                'https://tools.ietf.org/html/rfc6749#section-4.4');
        }


        $requestedScopes = $this->scopePolicyManager->scopeStringToArray($requestData['scope'] ?? null);
        $scopes = $this->scopePolicyManager->getScopes($tokenEndpoint->getClient(), $requestedScopes);

        $responseData = $this->issueAccessToken($scopes, $tokenEndpoint->getClient()->getIdentifier(), null);

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

    public function handleAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): array
    {
        throw new \BadMethodCallException();
    }

//    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
//    {
//        throw new \BadMethodCallException();
//    }

    public function getDefaultResponseMode(): string
    {
        throw new \BadMethodCallException();
    }

    public function getUnsupportedResponseModes(): array
    {
        throw new \BadMethodCallException();
    }

    public function isRegistrationOfRedirectUriRequired(): bool
    {
        throw new \BadMethodCallException();
    }
}
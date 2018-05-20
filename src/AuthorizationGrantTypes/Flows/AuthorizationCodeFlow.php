<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Credentials\AuthorizationCode;
use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;
use OAuth2\Helper;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

/**
 * Class AuthorizationCodeFlow
 * @package OAuth2\AuthorizationGrantTypes\Flows
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3.1
 * The authorization code is obtained by using an authorization server
 * as an intermediary between the client and resource owner.  Instead of
 * requesting authorization directly from the resource owner, the client
 * directs the resource owner to an authorization server (via its
 * user-agent as defined in [RFC2616]), which in turn directs the
 * resource owner back to the client with the authorization code.
 *
 * Before directing the resource owner back to the client with the
 * authorization code, the authorization server authenticates the
 * resource owner and obtains authorization.  Because the resource owner
 * only authenticates with the authorization server, the resource
 * owner's credentials are never shared with the client.
 *
 * The authorization code provides a few important security benefits,
 * such as the ability to authenticate the client, as well as the
 * transmission of the access token directly to the client without
 * passing it through the resource owner's user-agent and potentially
 * exposing it to others, including the resource owner.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.1
 * The authorization code grant type is used to obtain both access
 * tokens and refresh tokens and is optimized for confidential clients.
 * Since this is a redirection-based flow, the client must be capable of
 * interacting with the resource owner's user-agent (typically a web
 * browser) and capable of receiving incoming requests (via redirection)
 * from the authorization server.
 */
class AuthorizationCodeFlow extends AbstractGrantType implements FlowInterface
{
    protected $authorizationCodeStorage;
    /**
     * @var AuthorizationCode
     */
    protected $authorizationCode;

    public function __construct(AuthorizationCodeStorageInterface $authorizationCodeStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->authorizationCodeStorage = $authorizationCodeStorage;
    }

    /**
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.1     *
     * response_type
     * REQUIRED.  Value MUST be set to "code".
     */
    public function getResponseTypes(): array
    {
        return ['code'];
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
     * The client constructs the request URI by adding the following
     * parameters to the query component of the authorization endpoint URI
     * using the "application/x-www-form-urlencoded" format, per Appendix B:
     *
     * response_type
     * REQUIRED.  Value MUST be set to "code".
     *
     * client_id
     * REQUIRED.  The client identifier as described in Section 2.2.
     *
     * redirect_uri
     * OPTIONAL.  As described in Section 3.1.2.
     *
     * scope
     * OPTIONAL.  The scope of the access request as described by
     * Section 3.3.
     *
     * state
     * RECOMMENDED.  An opaque value used by the client to maintain
     * state between the request and callback.  The authorization
     * server includes this value when redirecting the user-agent back
     * to the client.  The parameter SHOULD be used for preventing
     * cross-site request forgery as described in Section 10.12.
     *
     * The client directs the resource owner to the constructed URI using an
     * HTTP redirection response, or by other means available to it via the
     * user-agent.
     *
     * For example, the client directs the user-agent to make the following
     * HTTP request using TLS (with extra line breaks for display purposes
     * only):
     *
     * GET /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz
     * &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb HTTP/1.1
     * Host: server.example.com
     *
     * The authorization server validates the request to ensure that all
     * required parameters are present and valid.  If the request is valid,
     * the authorization server authenticates the resource owner and obtains
     * an authorization decision (by asking the resource owner or by
     * establishing approval via other means).
     *
     * When a decision is established, the authorization server directs the
     * user-agent to the provided client redirection URI using an HTTP
     * redirection response, or by other means available to it via the
     * user-agent.
     */
    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
     * If the resource owner grants the access request, the authorization
     * server issues an authorization code and delivers it to the client by
     * adding the following parameters to the query component of the
     * redirection URI using the "application/x-www-form-urlencoded" format,
     * per Appendix B:
     *
     * code
     * REQUIRED.  The authorization code generated by the
     * authorization server.  The authorization code MUST expire
     * shortly after it is issued to mitigate the risk of leaks.  A
     * maximum authorization code lifetime of 10 minutes is
     * RECOMMENDED.  The client MUST NOT use the authorization code
     * more than once.  If an authorization code is used more than
     * once, the authorization server MUST deny the request and SHOULD
     * revoke (when possible) all tokens previously issued based on
     * that authorization code.  The authorization code is bound to
     * the client identifier and redirection URI.
     *
     * state
     * REQUIRED if the "state" parameter was present in the client
     * authorization request.  The exact value received from the
     * client.
     *
     * For example, the authorization server redirects the user-agent by
     * sending the following HTTP response:
     *
     * HTTP/1.1 302 Found
     * Location: https://client.example.com/cb?code=SplxlOBeZQQYbYS6WxSbIA
     * &state=xyz
     *
     * The client MUST ignore unrecognized response parameters.  The
     * authorization code string size is left undefined by this
     * specification.  The client should avoid making assumptions about code
     * value sizes.  The authorization server SHOULD document the size of
     * any value it issues.
     */
    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        $this->authorizationCode = $this->authorizationCodeStorage->generate(
            $authorizationEndpoint->getScopes(),
            $authorizationEndpoint->getClient()->getIdentifier(),
            $authorizationEndpoint->getResourceOwner()->getIdentifier(),
            $authorizationEndpoint->getRequestedScopes(),
            $requestData['redirect_uri'] ?? null
        );
        return ['code' => $this->authorizationCode->getCode()];
    }

    public function getDefaultResponseMode(): string
    {
        return 'query';
    }

    public function getUnsupportedResponseModes(): array
    {
        return [];
    }

    /**
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     * grant_type
     * REQUIRED.  Value MUST be set to "authorization_code".
     */
    public function getGrantTypes(): array
    {
        return ['authorization_code'];
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.3
     * The client makes a request to the token endpoint by sending the
     * following parameters using the "application/x-www-form-urlencoded"
     * format per Appendix B with a character encoding of UTF-8 in the HTTP
     * request entity-body:
     *
     * grant_type
     * REQUIRED.  Value MUST be set to "authorization_code".
     *
     * code
     * REQUIRED.  The authorization code received from the
     * authorization server.
     *
     * redirect_uri
     * REQUIRED, if the "redirect_uri" parameter was included in the
     * authorization request as described in Section 4.1.1, and their
     * values MUST be identical.
     *
     * client_id
     * REQUIRED, if the client is not authenticating with the
     * authorization server as described in Section 3.2.1.
     *
     * If the client type is confidential or the client was issued client
     * credentials (or assigned other authentication requirements), the
     * client MUST authenticate with the authorization server as described
     * in Section 3.2.1.
     *
     * For example, the client makes the following HTTP request using TLS
     * (with extra line breaks for display purposes only):
     *
     * POST /token HTTP/1.1
     * Host: server.example.com
     * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
     * Content-Type: application/x-www-form-urlencoded
     *
     * grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA
     * &redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
     *
     * The authorization server MUST:
     *
     * o  require client authentication for confidential clients or for any
     * client that was issued client credentials (or with other
     * authentication requirements),
     *
     * o  authenticate the client if client authentication is included,
     *
     * o  ensure that the authorization code was issued to the authenticated
     * confidential client, or if the client is public, ensure that the
     * code was issued to "client_id" in the request,
     *
     * o  verify that the authorization code is valid, and
     *
     * o  ensure that the "redirect_uri" parameter is present if the
     * "redirect_uri" parameter was included in the initial authorization
     * request as described in Section 4.1.1, and if included ensure that
     * their values are identical.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.4
     * If the access token request is valid and authorized, the
     * authorization server issues an access token and optional refresh
     * token as described in Section 5.1.  If the request client
     * authentication failed or is invalid, the authorization server returns
     * an error response as described in Section 5.2.
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (empty($requestData['code']) || !is_string($requestData['code'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter code.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }
        $code = $requestData['code'];

        // Todo, config should revoke tokens previously issued when authorization code is reused
        /**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
         * If an authorization code is used more than
         * once, the authorization server SHOULD
         * revoke (when possible) all tokens previously issued based on
         * that authorization code.
         */
        foreach ($this->accessTokenStorage->getByAuthorizationCode($code) as $token) {
            $this->accessTokenStorage->revoke($token);
        }
        foreach ($this->refreshTokenStorage->getByAuthorizationCode($code) as $token) {
            $this->refreshTokenStorage->revoke($token);
        }

        $this->authorizationCode = $this->authorizationCodeStorage->get($code);

        /**
         * ensure that the authorization code was issued to the authenticated
         * confidential client, or if the client is public, ensure that the
         * code was issued to "client_id" in the request,/**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
         * If an authorization code is used more than
         * once, the authorization server MUST deny the request.
         */
        if (!$this->authorizationCode ||
            $this->authorizationCode->getClientIdentifier() !== $tokenEndpoint->getClient()->getIdentifier()) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter code.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
         * The client MUST NOT use the authorization code
         * more than once.
         */
        $this->authorizationCodeStorage->revoke($code);

        /**
         * verify that the authorization code is valid
         */
        if ($this->authorizationCodeStorage->hasExpired($this->authorizationCode)) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter code. The code has expired.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        /**
         * ensure that the "redirect_uri" parameter is present if the
         * "redirect_uri" parameter was included in the initial authorization
         * request as described in Section 4.1.1, and if included ensure that
         * their values are identical.
         */
        if ($this->authorizationCode->getRedirectUri()) {
            if (empty($requestData['redirect_uri'])) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter redirect_uri',
                    'https://tools.ietf.org/html/rfc7636#section-4.1');
            }
            if ($requestData['redirect_uri'] !== $this->authorizationCode->getRedirectUri()) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter redirect_uri',
                    'https://tools.ietf.org/html/rfc7636#section-4.1');
            }
        }

        $responseData = $this->issueTokens(
            $this->authorizationCode->getScopes(),
            $this->authorizationCode->getClientIdentifier(),
            $this->authorizationCode->getResourceOwnerIdentifier(),
            $this->authorizationCode->getCode());

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.3
         * The authorization and token endpoints allow the client to specify the
         * scope of the access request using the "scope" request parameter.  In
         * turn, the authorization server uses the "scope" response parameter to
         * inform the client of the scope of the access token issued.
         */
        if (Helper::array_equals($this->authorizationCode->getRequestedScopes(), $this->authorizationCode->getScopes())) {
            $responseData['scope'] = implode(' ', $this->authorizationCode->getScopes());
        }

        return $responseData;
    }

    /**
     * @return AuthorizationCode
     */
    protected function getAuthorizationCode(): AuthorizationCode
    {
        return $this->authorizationCode;
    }
}
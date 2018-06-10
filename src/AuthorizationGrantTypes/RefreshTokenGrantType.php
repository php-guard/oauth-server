<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 14:36
 */

namespace OAuth2\AuthorizationGrantTypes;


use OAuth2\Config;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Helper;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

/**
 * Class RefreshTokenGrantType
 * @package OAuth2\AuthorizationGrantTypes
 *
 * @see https://tools.ietf.org/html/rfc6749#section-6
 * If the authorization server issued a refresh token to the client, the
 * client makes a refresh request to the token endpoint by adding the
 * following parameters using the "application/x-www-form-urlencoded"
 * format per Appendix B with a character encoding of UTF-8 in the HTTP
 * request entity-body:
 *
 * grant_type
 * REQUIRED.  Value MUST be set to "refresh_token".
 *
 * refresh_token
 * REQUIRED.  The refresh token issued to the client.
 *
 * scope
 * OPTIONAL.  The scope of the access request as described by
 * Section 3.3.  The requested scope MUST NOT include any scope
 * not originally granted by the resource owner, and if omitted is
 * treated as equal to the scope originally granted by the
 * resource owner.
 *
 * Because refresh tokens are typically long-lasting credentials used to
 * request additional access tokens, the refresh token is bound to the
 * client to which it was issued.  If the client type is confidential or
 * the client was issued client credentials (or assigned other
 * authentication requirements), the client MUST authenticate with the
 * authorization server as described in Section 3.2.1.
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
 * grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
 *
 * The authorization server MUST:
 *
 * o  require client authentication for confidential clients or for any
 * client that was issued client credentials (or with other
 * authentication requirements),
 *
 * o  authenticate the client if client authentication is included and
 * ensure that the refresh token was issued to the authenticated
 * client, and
 *
 * o  validate the refresh token.
 *
 * If valid and authorized, the authorization server issues an access
 * token as described in Section 5.1.  If the request failed
 * verification or is invalid, the authorization server returns an error
 * response as described in Section 5.2.
 *
 * The authorization server MAY issue a new refresh token, in which case
 * the client MUST discard the old refresh token and replace it with the
 * new refresh token.  The authorization server MAY revoke the old
 * refresh token after issuing a new refresh token to the client.  If a
 * new refresh token is issued, the refresh token scope MUST be
 * identical to that of the refresh token included by the client in the
 * request.
 */
class RefreshTokenGrantType extends AbstractGrantType implements GrantTypeInterface
{
    /**
     * @var Config
     */
    private $config;
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;

    public function __construct(AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage,
                                Config $config,
                                ScopePolicyManager $scopePolicyManager)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->config = $config;
        $this->scopePolicyManager = $scopePolicyManager;
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (empty($requestData['refresh_token'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter refresh_token.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $refreshToken = $this->refreshTokenStorage->get($requestData['refresh_token']);

        if (!$refreshToken || $refreshToken->getClientIdentifier() !== $tokenEndpoint->getClient()->getIdentifier()) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter refresh_token.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        if ($this->refreshTokenStorage->hasExpired($refreshToken)) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter refresh_token. The token has expired.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $scopes = $refreshToken->getScopes();
        $requestedScopes = $this->scopePolicyManager->scopeStringToArray($requestData['scope'] ?? null);

        if (!empty($requestedScopes)) {
            if (!empty(array_diff($requestedScopes, $refreshToken->getScopes()))) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter scope.',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
            $scopes = $requestedScopes;
        }

        $responseData = $this->issueAccessToken(
            $scopes,
            $refreshToken->getClientIdentifier(),
            $refreshToken->getResourceOwnerIdentifier(),
            $refreshToken->getAuthorizationCode()
        );

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

        if ($this->config->mayRevokeOldRefreshToken()) {
            $this->refreshTokenStorage->revoke($refreshToken);

            if ($this->config->mayIssueNewRefreshToken()) {
                $refreshToken = $this->refreshTokenStorage->generate(
                    $refreshToken->getScopes(),
                    $refreshToken->getClientIdentifier(),
                    $refreshToken->getResourceOwnerIdentifier(),
                    $refreshToken->getAuthorizationCode()
                );
                $responseData['refresh_token'] = $refreshToken->getToken();
            }
        }

        return $responseData;
    }
}
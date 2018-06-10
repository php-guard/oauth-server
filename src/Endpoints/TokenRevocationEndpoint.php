<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/06/2018
 * Time: 17:53
 */

namespace OAuth2\Endpoints;


use GuzzleHttp\Psr7\Response;
use OAuth2\ClientAuthentication\ClientAuthenticationMethodManager;
use OAuth2\Credentials\AccessTokenInterface;
use OAuth2\Credentials\RefreshTokenInterface;
use OAuth2\Credentials\TokenInterface;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Storages\StorageManager;
use OAuth2\Storages\TokenStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Class TokenRevocationEndpoint
 * @package OAuth2\Endpoints
 *
 * @see https://tools.ietf.org/html/rfc7009#section-2
 * Implementations MUST support the revocation of refresh tokens and
 * SHOULD support the revocation of access tokens (see Implementation
 * Note).
 *
 * The client requests the revocation of a particular token by making an
 * HTTP POST request to the token revocation endpoint URL.  This URL
 * MUST conform to the rules given in [RFC6749], Section 3.1.  Clients
 * MUST verify that the URL is an HTTPS URL.
 *
 * The means to obtain the location of the revocation endpoint is out of
 * the scope of this specification.  For example, the client developer
 * may consult the server's documentation or automatic discovery may be
 * used.  As this endpoint is handling security credentials, the
 * endpoint location needs to be obtained from a trustworthy source.
 *
 * Since requests to the token revocation endpoint result in the
 * transmission of plaintext credentials in the HTTP request, URLs for
 * token revocation endpoints MUST be HTTPS URLs.  The authorization
 * server MUST use Transport Layer Security (TLS) [RFC5246] in a version
 * compliant with [RFC6749], Section 1.6.  Implementations MAY also
 * support additional transport-layer security mechanisms that meet
 * their security requirements.
 *
 * If the host of the token revocation endpoint can also be reached over
 * HTTP, then the server SHOULD also offer a revocation service at the
 * corresponding HTTP URI, but it MUST NOT publish this URI as a token
 * revocation endpoint.  This ensures that tokens accidentally sent over
 * HTTP will be revoked.
 */
class TokenRevocationEndpoint implements EndpointInterface
{

    /**
     * @var ClientAuthenticationMethodManager
     */
    private $clientAuthenticationMethodManager;
    /**
     * @var StorageManager
     */
    private $storageManager;

    /**
     * TokenRevocationEndpoint constructor.
     * @param ClientAuthenticationMethodManager $clientAuthenticationMethodManager
     * @param StorageManager $storageManager
     */
    public function __construct(ClientAuthenticationMethodManager $clientAuthenticationMethodManager,
                                StorageManager $storageManager)
    {
        $this->clientAuthenticationMethodManager = $clientAuthenticationMethodManager;
        $this->storageManager = $storageManager;
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     *
     * @see https://tools.ietf.org/html/rfc7009#section-2.1
     * The client constructs the request by including the following
     * parameters using the "application/x-www-form-urlencoded" format in
     * the HTTP request entity-body:
     *
     * token   REQUIRED.  The token that the client wants to get revoked.
     *
     * token_type_hint  OPTIONAL.  A hint about the type of the token
     * submitted for revocation.  Clients MAY pass this parameter in
     * order to help the authorization server to optimize the token
     * lookup.  If the server is unable to locate the token using
     * the given hint, it MUST extend its search across all of its
     * supported token types.  An authorization server MAY ignore
     * this parameter, particularly if it is able to detect the
     * token type automatically.  This specification defines two
     * such values:
     * access_token: An access token as defined in [RFC6749],
     * Section 1.4
     * refresh_token: A refresh token as defined in [RFC6749],
     * Section 1.5
     *
     * Specific implementations, profiles, and extensions of this
     * specification MAY define other values for this parameter
     * using the registry defined in Section 4.1.2.
     *
     * The client also includes its authentication credentials as described
     * in Section 2.3. of [RFC6749].
     *
     * For example, a client may request the revocation of a refresh token
     * with the following request:
     *
     * POST /revoke HTTP/1.1
     * Host: server.example.com
     * Content-Type: application/x-www-form-urlencoded
     * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
     *
     * token=45ghiukldjahdnhzdauz&token_type_hint=refresh_token
     */
    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            return new Response(405);
        }

        $requestData = $request->getParsedBody();
        $token = $requestData['token'] ?? null;
        $tokenTypeHint = $requestData['token_type_hint'] ?? null;

        try {
            /**
             * @see https://tools.ietf.org/html/rfc7009#section-2.1
             * The authorization server first validates the client credentials (in
             * case of a confidential client) and then verifies whether the token
             * was issued to the client making the revocation request.  If this
             * validation fails, the request is refused and the client is informed
             * of the error by the authorization server as described below.
             */
            $client = $this->clientAuthenticationMethodManager->authenticate($request, $requestData);

            if (!$token) {
                throw new OAuthException('invalid_request',
                    'The token that the client wants to get revoked is required.',
                    'https://tools.ietf.org/html/rfc7009#section-2.1');
            }

            $token = $this->findToken($token, $tokenTypeHint);

            if ($token->getClientIdentifier() !== $client->getIdentifier()) {
                throw new OAuthException('unauthorized_client',
                    'The token that the client wants to get revoked was not issued to it.',
                    'https://tools.ietf.org/html/rfc7009#section-2.1');
            }

            /**
             * @see https://tools.ietf.org/html/rfc7009#section-2.1
             * In the next step, the authorization server invalidates the token.
             * The invalidation takes place immediately, and the token cannot be
             * used again after the revocation.  In practice, there could be a
             * propagation delay, for example, in which some servers know about the
             * invalidation while others do not.  Implementations should minimize
             * that window, and clients must not try to use the token after receipt
             * of an HTTP 200 response from the server.
             */
            $this->revokeToken($token);
        } catch (OAuthException $e) {
            $status = 400;
            $headers = ['Content-Type' => 'application/json'];
            if ($e->getError() === 'invalid_client') {
                $status = 401;
                if ($request->hasHeader('Authorization')) {
                    $headers['WWW-Authenticate'] = 'Basic';
                }
            }
            return new Response($status, $headers, $e->jsonSerialize());
        }

        /**
         * @see https://tools.ietf.org/html/rfc7009#section-2.2
         * The authorization server responds with HTTP status code 200 if the
         * token has been revoked successfully or if the client submitted an
         * invalid token.
         *
         * Note: invalid tokens do not cause an error response since the client
         * cannot handle such an error in a reasonable way.  Moreover, the
         * purpose of the revocation request, invalidating the particular token,
         * is already achieved.
         *
         * The content of the response body is ignored by the client as all
         * necessary information is conveyed in the response code.
         *
         * An invalid token type hint value is ignored by the authorization
         * server and does not influence the revocation response.
         */
        return new Response(200);
    }

    /**
     * @return TokenStorageInterface[]
     */
    protected function getStorages(): array
    {
        return [
            'access_token' => $this->storageManager->getAccessTokenStorage(),
            'refresh_token' => $this->storageManager->getRefreshTokenStorage()
        ];
    }

    protected function findToken(string $token, ?string $tokenTypeHint = null): ?TokenInterface
    {
        $storages = $this->getStorages();

        if ($tokenTypeHint && isset($storages[$tokenTypeHint])) {
            $storage = $storages[$tokenTypeHint];
            unset($storages[$tokenTypeHint]);
            if ($tokenFound = $storage->get($token)) {
                return $tokenFound;
            }
        }

        foreach ($storages as $storage) {
            if ($tokenFound = $storage->get($token)) {
                return $tokenFound;
            }
        }

        return null;
    }

    /**
     * @param TokenInterface $token
     *
     * @see https://tools.ietf.org/html/rfc7009#section-2.1
     * Depending on the authorization server's revocation policy, the
     * revocation of a particular token may cause the revocation of related
     * tokens and the underlying authorization grant.  If the particular
     * token is a refresh token and the authorization server supports the
     * revocation of access tokens, then the authorization server SHOULD
     * also invalidate all access tokens based on the same authorization
     * grant (see Implementation Note).  If the token passed to the request
     * is an access token, the server MAY revoke the respective refresh
     * token as well.
     */
    protected function revokeToken(TokenInterface $token)
    {
        $accessTokenStorage = $this->storageManager->getAccessTokenStorage();
        $refreshTokenStorage = $this->storageManager->getRefreshTokenStorage();

        if ($token instanceof AccessTokenInterface) {
            $accessTokenStorage->revoke($token);
            if ($refreshToken = $token->getRefreshToken()) {
                if ($refreshToken = $refreshTokenStorage->get($refreshToken)) {
                    $refreshTokenStorage->revoke($refreshToken);
                }
            }
        } else if ($token instanceof RefreshTokenInterface) {
            $refreshTokenStorage->revoke($token);
            foreach ($this->storageManager->getAccessTokenStorage()->getByRefreshToken($token) as $accessToken) {
                $accessTokenStorage->revoke($accessToken);
            }
        }
    }
}
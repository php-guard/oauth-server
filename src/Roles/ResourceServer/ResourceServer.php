<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 27/05/2018
 * Time: 17:46
 */

namespace OAuth2\Roles\ResourceServer;


use GuzzleHttp\Psr7\Response;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\AuthorizationRequestHeaderField;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\BearerAuthenticationMethodInterface;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\FormEncodedBodyParameter;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\URIQueryParameter;
use OAuth2\Roles\ResourceServerInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ResourceServer implements ResourceServerInterface
{
    /**
     * @var StorageManager
     */
    private $storageManager;

    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;

    /**
     * @var BearerAuthenticationMethodInterface[]
     */
    private $bearerAuthenticationMethods = [];

    /**
     * @var AuthenticatedRequest|null
     */
    private $authenticatedRequest;

    public function __construct(StorageManager $storageManager,
                                ScopePolicyManager $scopePolicyManager)
    {
        $this->storageManager = $storageManager;
        $this->scopePolicyManager = $scopePolicyManager;

        $this->bearerAuthenticationMethods = [
            /**
             * @see https://tools.ietf.org/html/rfc6750#section-2
             * Clients MUST NOT use more than one method to transmit the token in each request.
             */
            new AuthorizationRequestHeaderField()
        ];
    }

    /**
     * @param ServerRequestInterface $request
     * @param null|string $realm
     * @param null|string $scope
     * @return null|ResponseInterface
     */
    public function verifyRequest(ServerRequestInterface $request, ?string $realm = null, ?string $scope = null): ?ResponseInterface
    {
        try {
            $bearerAuthenticationMethodUsed = null;
            foreach ($this->bearerAuthenticationMethods as $bearerAuthenticationMethod) {
                if ($bearerAuthenticationMethod->support($request)) {
                    /**
                     * @see https://tools.ietf.org/html/rfc6750#section-2
                     * Clients MUST NOT use more than one method to transmit the token in each request.
                     */
                    if ($bearerAuthenticationMethodUsed) {
                        throw new OAuthException('invalid_request',
                            'The request utilizes more than one mechanism for authenticating the client.',
                            'https://tools.ietf.org/html/rfc6749#section-3.2.1');
                    }

                    $bearerAuthenticationMethodUsed = $bearerAuthenticationMethod;
                }
            }

            /**
             * https://tools.ietf.org/html/rfc6750#section-3
             * If the protected resource request does not include authentication
             * credentials or does not contain an access token that enables access
             * to the protected resource, the resource server MUST include the HTTP
             * "WWW-Authenticate" response header field; it MAY include it in
             * response to other conditions as well.  The "WWW-Authenticate" header
             * field uses the framework defined by HTTP/1.1 [RFC2617].
             *
             * @see https://tools.ietf.org/html/rfc6750#section-3.1
             * If the request lacks any authentication information (e.g., the client
             * was unaware that authentication is necessary or attempted using an
             * unsupported authentication method), the resource server SHOULD NOT
             * include an error code or other error information.
             *
             * For example:
             *
             * HTTP/1.1 401 Unauthorized
             * WWW-Authenticate: Bearer realm="example"
             */
            if (!$bearerAuthenticationMethodUsed) {
                return new Response(401, ['WWW-Authenticate' => 'Bearer' . ($realm ? ' realm="example"' : '')]);
            }

            $token = $bearerAuthenticationMethodUsed->authenticate($request);

            if (!$token) {
                throw new OAuthException('invalid_request',
                    'The request is missing a required parameter, includes an unsupported parameter or parameter value',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            $accessTokenStorage = $this->storageManager->getAccessTokenStorage();

            if (!$accessToken = $accessTokenStorage->get($token)) {
                throw new OAuthException('invalid_token',
                    'The access token provided is invalid.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            if ($accessTokenStorage->hasExpired($accessToken)) {
                throw new OAuthException('invalid_token',
                    'The access token provided is expired.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            if (!$client = $this->storageManager->getClientStorage()->get($accessToken->getClientIdentifier())) {
                throw new OAuthException('invalid_token',
                    'The access token provided is invalid. Client not found.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            $resourceOwner = null;
            if ($accessToken->getResourceOwnerIdentifier()) {
                if (!$resourceOwner = $this->storageManager->getResourceOwnerStorage()->get($accessToken->getResourceOwnerIdentifier())) {
                    throw new OAuthException('invalid_token',
                        'The access token provided is invalid. Resource owner not found.',
                        'https://tools.ietf.org/html/rfc6750#section-3.1');
                }
            }

            $requiredScopes = $this->scopePolicyManager->scopeStringToArray($scope);
            if (!empty($requiredScopes) && !empty(array_diff($requiredScopes, $accessToken->getScopes()))) {
                throw new OAuthException('insufficient_scope',
                    'The request requires higher privileges than provided by the access token.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }
        } catch (OAuthException $e) {
            /**
             * @see https://tools.ietf.org/html/rfc6750#section-3
             * If the protected resource request included an access token and failed
             * authentication, the resource server SHOULD include the "error"
             * attribute to provide the client with the reason why the access
             * request was declined.  The parameter value is described in
             * Section 3.1.  In addition, the resource server MAY include the
             * "error_description" attribute to provide developers a human-readable
             * explanation that is not meant to be displayed to end-users.  It also
             * MAY include the "error_uri" attribute with an absolute URI
             * identifying a human-readable web page explaining the error.  The
             * "error", "error_description", and "error_uri" attributes MUST NOT
             * appear more than once.
             *
             * @see https://tools.ietf.org/html/rfc6750#section-3.1
             * When a request fails, the resource server responds using the
             * appropriate HTTP status code (typically, 400, 401, 403, or 405) and
             * includes one of the following error codes in the response:
             *
             * invalid_request
             * The request is missing a required parameter, includes an
             * unsupported parameter or parameter value, repeats the same
             * parameter, uses more than one method for including an access
             * token, or is otherwise malformed.  The resource server SHOULD
             * respond with the HTTP 400 (Bad Request) status code.
             *
             * invalid_token
             * The access token provided is expired, revoked, malformed, or
             * invalid for other reasons.  The resource SHOULD respond with
             * the HTTP 401 (Unauthorized) status code.  The client MAY
             * request a new access token and retry the protected resource
             * request.
             *
             * insufficient_scope
             * The request requires higher privileges than provided by the
             * access token.  The resource server SHOULD respond with the HTTP
             * 403 (Forbidden) status code and MAY include the "scope"
             * attribute with the scope necessary to access the protected
             * resource.
             */
            switch ($e->getError()) {
                case 'invalid_token':
                    $statusCode = 401;
                    break;
                case 'insufficient_scope':
                    $statusCode = 403;
                    break;
                default:
                    $statusCode = 400;
            }

            $header = 'Bearer';
            if ($realm) {
                $header .= ' realm="' . $realm . '"';
            }
            $header .= ' error="' . $e->getError() . '"';
            if ($e->getErrorDescription()) {
                $header .= ' error_description="' . $e->getErrorDescription() . '"';
            }
            if ($e->getErrorUri()) {
                $header .= ' error_uri="' . $e->getErrorUri() . '"';
            }

            return new Response($statusCode, ['WWW-Authenticate' => $header]);
        }

        $this->authenticatedRequest = new AuthenticatedRequest($request, $client, $resourceOwner, $accessToken);
        return null;
    }

    public function addBearerAuthenticationMethod(BearerAuthenticationMethodInterface $method): self
    {
        $this->bearerAuthenticationMethods[] = $method;

        return $this;
    }

    /**
     * @return AuthenticatedRequest|null
     */
    public function getAuthenticatedRequest(): ?AuthenticatedRequest
    {
        return $this->authenticatedRequest;
    }
}
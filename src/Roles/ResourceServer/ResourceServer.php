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
use OAuth2\Roles\ResourceServerInterface;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\ClientStorageInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class ResourceServer implements ResourceServerInterface
{
    /**
     * @var BearerAuthenticationMethodInterface[]
     */
    private $bearerAuthenticationMethods = [];
    /**
     * @var AccessTokenStorageInterface
     */
    private $accessTokenStorage;
    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;
    /**
     * @var ResourceOwnerStorageInterface
     */
    private $resourceOwnerStorage;

    /**
     * @var AuthenticatedRequest|null
     */
    private $authenticatedRequest;

    public function __construct(AccessTokenStorageInterface $accessTokenStorage,
                                ClientStorageInterface $clientStorage,
                                ResourceOwnerStorageInterface $resourceOwnerStorage)
    {
        $this->bearerAuthenticationMethods = [
            /**
             * Resource servers MUST support this method
             * @see https://tools.ietf.org/html/rfc6750#section-2.1
             */
            new AuthorizationRequestHeaderField()
        ];
        $this->accessTokenStorage = $accessTokenStorage;
        $this->clientStorage = $clientStorage;
        $this->resourceOwnerStorage = $resourceOwnerStorage;
    }

    /**
     * @param ServerRequestInterface $request
     * @return null|ResponseInterface
     * @throws OAuthException
     */
    public function verifyRequest(ServerRequestInterface $request, array $requiredScopes, ?string $realm = null): ?ResponseInterface
    {
        try {
            $bearerAuthenticationMethodUsed = null;
            foreach ($this->bearerAuthenticationMethods as $bearerAuthenticationMethod) {
                if ($bearerAuthenticationMethod->support($request)) {
                    if ($bearerAuthenticationMethodUsed) {
                        throw new OAuthException('invalid_request',
                            'The request utilizes more than one mechanism for authenticating the client.',
                            'https://tools.ietf.org/html/rfc6749#section-3.2.1');
                    }

                    $bearerAuthenticationMethodUsed = $bearerAuthenticationMethod;
                }
            }

            /**
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

            if (!$accessToken = $this->accessTokenStorage->get($token)) {
                throw new OAuthException('invalid_token',
                    'The access token provided is invalid.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            if ($this->accessTokenStorage->hasExpired($accessToken)) {
                throw new OAuthException('invalid_token',
                    'The access token provided is expired.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            if (!$client = $this->clientStorage->get($accessToken->getClientIdentifier())) {
                throw new OAuthException('invalid_token',
                    'The access token provided is invalid. Client not found.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }

            $resourceOwner = null;
            if ($accessToken->getResourceOwnerIdentifier()) {
                if (!$resourceOwner = $this->resourceOwnerStorage->get($accessToken->getResourceOwnerIdentifier())) {
                    throw new OAuthException('invalid_token',
                        'The access token provided is invalid. Resource owner not found.',
                        'https://tools.ietf.org/html/rfc6750#section-3.1');
                }
            }

            if (!empty(array_diff($requiredScopes, $accessToken->getScopes()))) {
                throw new OAuthException('insufficient_scope',
                    'The request requires higher privileges than provided by the access token.',
                    'https://tools.ietf.org/html/rfc6750#section-3.1');
            }
        } catch (OAuthException $e) {
            switch ($e->getError()) {
                case 'invalid_token':
                    $statusCode = 401;
                    break;
                case 'insufficient_scope':
                    $statusCode = 403;
                default:
                    $statusCode = 400;
            }

            $header = 'Bearer';
            if ($realm) {
                $header .= ' realm="' . $realm . '"';
            }
            $header .= ' error="'.$e->getError().'"';
            if($e->getErrorDescription()) {
                $header .= ' error_description="'.$e->getErrorDescription().'"';
            }
            if($e->getErrorUri()) {
                $header .= ' error_uri="'.$e->getErrorUri().'"';
            }

            return new Response($statusCode, ['WWW-Authenticate' => $header]);
        }

        $this->authenticatedRequest = new AuthenticatedRequest($request, $client, $resourceOwner, $accessToken->getScopes());
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
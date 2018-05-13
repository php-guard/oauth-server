<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 22:22
 */

namespace OAuth2\Endpoints;


use GuzzleHttp\Psr7\Response;
use OAuth2\ClientAuthentication\ClientAuthenticationMethodManager;
use OAuth2\Exceptions\OAuthException;
use OAuth2\AuthorizationGrantTypes\GrantTypeInterface;
use OAuth2\AuthorizationGrantTypes\GrantTypeManager;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class TokenEndpoint
 * @package OAuth2\Endpoints
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.2
 * The token endpoint is used by the client to obtain an access token by
 * presenting its authorization grant or refresh token.  The token
 * endpoint is used with every authorization grant except for the
 * implicit grant type (since an access token is issued directly).
 *
 * The means through which the client obtains the location of the token
 * endpoint are beyond the scope of this specification, but the location
 * is typically provided in the service documentation.
 *
 * The endpoint URI MAY include an "application/x-www-form-urlencoded"
 * formatted (per Appendix B) query component ([RFC3986] Section 3.4),
 * which MUST be retained when adding additional query parameters.  The
 * endpoint URI MUST NOT include a fragment component.
 *
 * Since requests to the token endpoint result in the transmission of
 * clear-text credentials (in the HTTP request and response), the
 * authorization server MUST require the use of TLS as described in
 * Section 1.6 when sending requests to the token endpoint.
 *
 * The client MUST use the HTTP "POST" method when making access token
 * requests.
 *
 * Parameters sent without a value MUST be treated as if they were
 * omitted from the request.  The authorization server MUST ignore
 * unrecognized request parameters.  Request and response parameters
 * MUST NOT be included more than once.
 */
class TokenEndpoint implements EndpointInterface
{

    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;
    /**
     * @var GrantTypeManager
     */
    private $grantTypeManager;
    /**
     * @var ClientAuthenticationMethodManager
     */
    private $clientAuthenticationMethodManager;

    /**
     * @var RegisteredClient|null
     */
    protected $client;
    /**
     * @var GrantTypeInterface|null
     */
    protected $grantType;

    public function __construct(ClientStorageInterface $clientStorage,
                                GrantTypeManager $grantTypeManager,
                                ClientAuthenticationMethodManager $clientAuthenticationMethodManager)
    {
        $this->clientStorage = $clientStorage;
        $this->grantTypeManager = $grantTypeManager;
        $this->clientAuthenticationMethodManager = $clientAuthenticationMethodManager;
    }

    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() === 'POST') {
            $requestData = $request->getParsedBody();
        } else {
            return new Response(404);
        }

        try {
            // Authentication Request Validation
            // The Authorization Server MUST validate all the OAuth 2.0 parameters according to the OAuth 2.0 specification.
            $this->verifyRequestData($request, $requestData);

            $responseData = $this->getGrantType()->handleAccessTokenRequest($this, $requestData);

        } catch (OAuthException $e) {
            /**
             * If the Authorization Server encounters any error, it MUST return an error response, per Section 5.2
             */
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

        return new Response(200, [
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache'
        ], json_encode($responseData));
    }

    /**
     * @param ServerRequestInterface $request
     * @param array $requestData
     * @throws OAuthException
     */
    protected function verifyRequestData(ServerRequestInterface $request, array $requestData)
    {
        if (empty($requestData['grant_type'])) {
            throw new OAuthException('invalid_request', 'The request is missing the required parameter grant_type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if (!($grantType = $this->grantTypeManager->getGrantType($requestData['grant_type']))) {
            throw new OAuthException('unsupported_grant_type',
                'The authorization grant type is not supported by the authorization server',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        $this->grantType = $grantType;

        $this->verifyClient($request, $requestData);

        $supportedGrantTypes = $this->client->getMetadata()->getGrantTypes() ?: ['authorization_code'];
        if (!in_array($requestData['grant_type'], $supportedGrantTypes)) {
            throw new OAuthException('unauthorized_client',
                'The authenticated client is not authorized to use this authorization grant type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

    }

    /**
     * @param ServerRequestInterface $request
     * @param array $requestData
     * @throws OAuthException
     */
    protected function verifyClient(ServerRequestInterface $request, array $requestData)
    {
        $this->client = $this->clientAuthenticationMethodManager->authenticate($request, $requestData);
        $this->getGrantType();
    }

    /**
     * @return null|GrantTypeInterface
     */
    public function getGrantType()
    {
        return $this->grantType;
    }

    /**
     * @return null|RegisteredClient
     */
    public function getClient(): ?RegisteredClient
    {
        return $this->client;
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:14
 */

namespace OAuth2\Endpoints;


use GuzzleHttp\Psr7\Response;
use GuzzleHttp\Psr7\Uri;
use OAuth2\Exceptions\OAuthException;
use OAuth2\ResponseModes\ResponseModeInterface;
use OAuth2\ResponseModes\ResponseModeManager;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeInterface;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeManager;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ClientTypes\ConfidentialClientInterface;
use OAuth2\Roles\ClientTypes\PublicClient;
use OAuth2\Roles\ClientTypes\PublicClientInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Roles\ResourceOwnerInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class AuthorizationEndpoint
 * @package OAuth2\Endpoints
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.1
 * The authorization endpoint is used to interact with the resource
 * owner and obtain an authorization grant.  The authorization server
 * MUST first verify the identity of the resource owner.  The way in
 * which the authorization server authenticates the resource owner
 * (e.g., username and password login, session cookies) is beyond the
 * scope of this specification.
 *
 * The means through which the client obtains the location of the
 * authorization endpoint are beyond the scope of this specification,
 * but the location is typically provided in the service documentation.
 *
 * The endpoint URI MAY include an "application/x-www-form-urlencoded"
 * formatted (per Appendix B) query component ([RFC3986] Section 3.4),
 * which MUST be retained when adding additional query parameters.  The
 * endpoint URI MUST NOT include a fragment component.
 *
 * Since requests to the authorization endpoint result in user
 * authentication and the transmission of clear-text credentials (in the
 * HTTP response), the authorization server MUST require the use of TLS
 * as described in Section 1.6 when sending requests to the
 * authorization endpoint.
 *
 * The authorization server MUST support the use of the HTTP "GET"
 * method [RFC2616] for the authorization endpoint and MAY support the
 * use of the "POST" method as well.
 *
 * Parameters sent without a value MUST be treated as if they were
 * omitted from the request.  The authorization server MUST ignore
 * unrecognized request parameters.  Request and response parameters
 * MUST NOT be included more than once.
 */
class AuthorizationEndpoint implements EndpointInterface
{
    /**
     * @var ResponseTypeManager
     */
    protected $responseTypeManager;
    /**
     * @var ResponseTypeInterface|null
     */
    private $responseType;
    /**
     * @var ResponseModeManager
     */
    protected $responseModeManager;
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;
    /**
     * @var ResponseModeInterface|null
     */
    private $responseMode;
    /**
     * @var ResourceOwnerInterface
     */
    private $resourceOwner;
    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;
    /**
     * @var RegisteredClient|null
     */
    private $client;
    /**
     * @var Uri|null
     */
    private $redirectUri;
    /**
     * @var string|null
     */
    private $state;
    /**
     * @var array|null
     */
    private $scopes;
    /**
     * @var array|null
     */
    private $requestedScopes;
    /**
     * @var array|null
     */
    private $requestData;

    public function __construct(ResponseTypeManager $responseTypeManager,
                                ResponseModeManager $responseModeManager,
                                ScopePolicyManager $scopePolicyManager,
                                ResourceOwnerInterface $resourceOwner,
                                ClientStorageInterface $clientStorage)
    {
        $this->responseTypeManager = $responseTypeManager;
        $this->responseModeManager = $responseModeManager;
        $this->scopePolicyManager = $scopePolicyManager;
        $this->resourceOwner = $resourceOwner;
        $this->clientStorage = $clientStorage;
    }

    public function verifyRequest(ServerRequestInterface $request): ?ResponseInterface
    {

        if ($response = $this->parseRequestData($request)) {
            return $response;
        }

        try {
            $this->verifyClient($this->requestData['client_id'] ?? null);
            $this->verifyRedirectUri($this->requestData['redirect_uri'] ?? null, $this->requestData['response_type'] ?? null);
        } catch (OAuthException $e) {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
             * If the request fails due to a missing, invalid, or mismatching
             * redirection URI, or if the client identifier is missing or invalid,
             * the authorization server SHOULD inform the resource owner of the
             * error and MUST NOT automatically redirect the user-agent to the
             * invalid redirection URI.
             */
            return new Response(400, ['content-type' => 'application/json'], $e->jsonSerialize());
        }

        try {
            $this->verifyRequestData($this->requestData);
            $this->responseType->verifyAuthorizationRequest($this, $this->requestData);

            // Authorization Server Authenticates End-User
            if ($response = $this->verifyResourceOwner()) {
                return $response;
            }
        } catch (OAuthException $e) {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
             * If the resource owner denies the access request or if the request
             * fails for reasons other than a missing or invalid redirection URI,
             * the authorization server informs the client by adding the following
             * parameters to the query component of the redirection URI using the
             * "application/x-www-form-urlencoded" format, per Appendix B:
             *
             * error
             * REQUIRED.  A single ASCII [USASCII] error code
             *
             * error_description
             * OPTIONAL.  Human-readable ASCII [USASCII] text providing
             * additional information, used to assist the client developer in
             * understanding the error that occurred.
             * Values for the "error_description" parameter MUST NOT include
             * characters outside the set %x20-21 / %x23-5B / %x5D-7E.
             *
             * error_uri
             * OPTIONAL.  A URI identifying a human-readable web page with
             * information about the error, used to provide the client
             * developer with additional information about the error.
             * Values for the "error_uri" parameter MUST conform to the
             * URI-reference syntax and thus MUST NOT include characters
             * outside the set %x21 / %x23-5B / %x5D-7E.
             *
             * state
             * REQUIRED if a "state" parameter was present in the client
             * authorization request.  The exact value received from the
             * client.
             *
             */
            $responseData = [
                'error' => $e->getError()
            ];
            if ($e->getErrorDescription()) {
                $responseData['error_description'] = $e->getErrorDescription();
            }
            if ($e->getErrorUri()) {
                $responseData['error_uri'] = $e->getErrorUri();
            }

            if (!empty($this->state)) {
                $responseData['state'] = $this->state;
            }

            return $this->getResponseMode()->buildResponse($this, $this->requestData, $responseData);
        }

        return null;
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
     * The client constructs the request URI by adding the following
     * parameters to the query component of the authorization endpoint URI
     * using the "application/x-www-form-urlencoded" format, per Appendix B:
     *
     * response_type
     * REQUIRED.  Value MUST be set to [desired response type].
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
     */
    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        /**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
         * The authorization server validates the request to ensure that all
         * required parameters are present and valid.
         */
        if ($response = $this->verifyRequest($request)) {
            return $response;
        }

        try {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
             * If the request is valid,
             * the authorization server authenticates the resource owner and obtains
             * an authorization decision (by asking the resource owner or by
             * establishing approval via other means).
             */
            if ($response = $this->verifyConsent($this->requestData)) {
                return $response;
            }

            $responseData = $this->getResponseType()->handleAuthorizationRequest($this, $this->requestData);
        } catch (OAuthException $e) {
            /**
             * If the Authorization Server encounters any error, it MUST return an error response, per Section 3.1.2.6.
             */
            $responseData = [
                'error' => $e->getError()
            ];
            if ($e->getErrorDescription()) {
                $responseData['error_description'] = $e->getErrorDescription();
            }
            if ($e->getErrorUri()) {
                $responseData['error_uri'] = $e->getErrorUri();
            }
        }

        if (!empty($this->state)) {
            $responseData['state'] = $this->state;
        }

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
         * When a decision is established, the authorization server directs the
         * user-agent to the provided client redirection URI using an HTTP
         * redirection response, or by other means available to it via the
         * user-agent.
         */
        return $this->getResponseMode()->buildResponse($this, $this->requestData, $responseData);
    }

    protected function parseRequestData(ServerRequestInterface $request): ?Response
    {
        if ($request->getMethod() === 'GET') {
            $this->requestData = $request->getQueryParams();
        } else if ($request->getMethod() === 'POST') {
            $this->requestData = is_array($request->getParsedBody()) ? $request->getParsedBody() : [];
        } else {
            return new Response(404);
        }
        return null;
    }

    protected function verifyResourceOwner(): ?ResponseInterface
    {
        if (!$this->resourceOwner->isAuthenticated()) {
            return $this->resourceOwner->authenticate();
        }
        return null;
    }

    /**
     * @param array $requestData
     * @return null|ResponseInterface
     * @throws OAuthException
     */
    protected function verifyConsent(array $requestData): ?ResponseInterface
    {
        $consentGiven = $this->resourceOwner->hasGivenConsent($this->getClient(), $this->getScopes());
        if (is_null($consentGiven)) {
            return $this->resourceOwner->obtainConsent($this, $requestData);
        }

        if (empty($consentGiven)) {
            throw new OAuthException('access_denied', 'The resource owner denied the request.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        return null;
    }

    /**
     * @param null|string $clientId
     * @throws OAuthException
     */
    protected function verifyClient(?string $clientId = null)
    {
        if (empty($clientId)) {
            throw new OAuthException('invalid_request', 'The request is missing the required parameter client_id.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if (!($client = $this->clientStorage->get($clientId))) {
            throw new OAuthException('invalid_request', 'The request includes the invalid parameter client_id.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }
        $this->client = $client;
    }

    /**
     * @param array $requestData
     * @throws OAuthException
     */
    protected function verifyRequestData(array $requestData)
    {
        // set the default response in case of invalid response type

        $this->responseMode = $this->responseModeManager->getDefaultResponseMode();

        // response_type required
        if (empty($requestData['response_type'])) {
            throw new OAuthException('invalid_request', 'The request is missing the required parameter response_type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if (!($responseType = $this->responseTypeManager->getResponseType($requestData['response_type']))) {
            throw new OAuthException('invalid_request', 'The request includes the invalid parameter response_type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }
        $this->responseType = $responseType;

        $supportedResponseTypes = $this->client->getMetadata()->getResponseTypes() ?: ['code'];
        foreach (explode(' ', $requestData['response_type']) as $responseType) {
            if (!in_array($responseType, $supportedResponseTypes)) {
                throw new OAuthException('unsupported_response_type',
                    'The authorization server does not support obtaining an authorization code using this method.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }
        }

        $this->verifyScope($requestData['scope'] ?? null);

        $this->state = $requestData['state'] ?? null;

        $responseModeIdentifier = $requestData['response_mode'] ?? $this->getResponseType()->getDefaultResponseMode();
        if (!($responseMode = $this->responseModeManager->getResponseMode($responseModeIdentifier))) {
            throw new OAuthException('invalid_request', 'response_mode invalid');
        }

        if (in_array($responseModeIdentifier, $this->getResponseType()->getUnsupportedResponseModes())) {
            throw new OAuthException('invalid_request', 'response_mode unsupported');
        }

        $this->responseMode = $responseMode;
    }

    /**
     * @param null|string $redirectUri
     * @param null|string $responseType
     * @throws OAuthException
     */
    protected function verifyRedirectUri(?string $redirectUri = null, ?string $responseType = null)
    {
        $redirectUris = $this->getClient()->getMetadata()->getRedirectUris();
        if (empty($redirectUris)) {
            if ($this->getClient() instanceof PublicClientInterface ||
                ($this->getClient() instanceof ConfidentialClientInterface && $responseType == 'token'))
                throw new OAuthException('invalid_request',
                    'Clients using flows with redirection MUST register their redirection URI values',
                    'https://tools.ietf.org/html/rfc7591#section-2.1');
        } else {
            if ($redirectUri) {
                if (!in_array($redirectUri, $redirectUris)) {
                    throw new OAuthException('invalid_request', 'The request includes the invalid parameter redirect_uri.',
                        'https://tools.ietf.org/html/rfc6749#section-4.1');
                }
            } else {
                if (count($redirectUris) == 1) {
                    $redirectUri = $redirectUris[0];
                } else {
                    throw new OAuthException('invalid_request', 'The request is missing the required parameter redirect_uri.',
                        'https://tools.ietf.org/html/rfc6749#section-4.1');
                }
            }
        }

        try {
            $redirectUri = new Uri($redirectUri);
            if ($redirectUri->getFragment()) {
                throw new \InvalidArgumentException('The endpoint URI must not include a fragment component.');
            }

            $this->redirectUri = $redirectUri;
        } catch (\InvalidArgumentException $e) {
            throw new OAuthException('invalid_request', 'The request includes the malformed parameter redirect_uri. ' . $e->getMessage(),
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }
    }

    /**
     * @param null|string $scope
     * @throws OAuthException
     */
    protected function verifyScope(?string $scope = null)
    {
        $this->scopes = $this->scopePolicyManager->getScopes($this->getClient(), $scope, $requestedScopes);
        $this->requestedScopes = $requestedScopes;
    }

    /**
     * @return null|ResponseTypeInterface
     */
    public function getResponseType(): ?ResponseTypeInterface
    {
        return $this->responseType;
    }

    /**
     * @return null|ResponseModeInterface
     */
    public function getResponseMode(): ?ResponseModeInterface
    {
        return $this->responseMode;
    }

    /**
     * @return null|RegisteredClient
     */
    public function getClient(): ?RegisteredClient
    {
        return $this->client;
    }

    /**
     * @return Uri|null
     */
    public function getRedirectUri(): ?Uri
    {
        return $this->redirectUri;
    }

    /**
     * @return null|string
     */
    public function getState(): ?string
    {
        return $this->state;
    }

    /**
     * @return null|array
     */
    public function getScopes(): ?array
    {
        return $this->scopes;
    }

    /**
     * @return null|array
     */
    public function getRequestedScopes(): ?array
    {
        return $this->requestedScopes;
    }

    /**
     * @return null|array
     */
    public function getRequestData(): ?array
    {
        return $this->requestData;
    }

    /**
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        return $this->resourceOwner;
    }
}
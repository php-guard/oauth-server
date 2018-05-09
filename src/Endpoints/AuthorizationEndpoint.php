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
use OAuth2\ResponseTypes\ResponseTypeInterface;
use OAuth2\ResponseTypes\ResponseTypeManager;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\Clients\RegisteredClient;
use OAuth2\Roles\ResourceOwnerInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

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

    public function verifyRequest(ServerRequestInterface $request): ?ResponseInterface {

        if($response = $this->parseRequestData($request)) {
            return $response;
        }

        try {
            $this->verifyClient($this->requestData['client_id'] ?? null);
            $this->verifyRedirectUri($this->requestData['redirect_uri'] ?? null);

        } catch (OAuthException $e) {
            return new Response(400, ['content-type' => 'application/json'], $e->jsonSerialize());
        }

        try {
            $this->verifyRequestData($this->requestData);
            $this->responseType->verifyAuthorizationRequest($this, $this->requestData);

            // Authorization Server Authenticates End-User
            if($response = $this->verifyResourceOwner()) {
                return $response;
            }
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

            if (!empty($this->state)) {
                $responseData['state'] = $this->state;
            }

            return $this->getResponseMode()->buildResponse($this, $this->requestData, $responseData);
        }

        return null;
    }

    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
       if($response = $this->verifyRequest($request)) {
           return $response;
       }

        try {
            if($response = $this->verifyConsent($this->requestData)) {
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

        return $this->getResponseMode()->buildResponse($this, $this->requestData, $responseData);
    }

    protected function parseRequestData(ServerRequestInterface $request): ?Response {
        if ($request->getMethod() === 'GET') {
            $this->requestData = $request->getQueryParams();
        } else if ($request->getMethod() === 'POST') {
            $this->requestData = is_array($request->getParsedBody()) ? $request->getParsedBody() : [];
        } else {
            return new Response(404);
        }
        return null;
    }

    protected function verifyResourceOwner(): ?ResponseInterface {
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
    protected function verifyConsent(array $requestData): ?ResponseInterface {
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
    protected function verifyClient(?string $clientId = null) {
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
     * @throws OAuthException
     */
    protected function verifyRedirectUri(?string $redirectUri = null)
    {
        $redirectUris = $this->getClient()->getMetadata()->getRedirectUris();
        if(empty($redirectUris)) {
            throw new OAuthException('invalid_request',
                'Clients using flows with redirection MUST register their redirection URI values',
                'https://tools.ietf.org/html/rfc7591#section-2.1');
        }

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
        $scopes = $this->scopePolicyManager->getScopes($this->getClient(), $scope, $requestedScopes);
        $this->requestedScopes = $requestedScopes;
        
        $this->scopePolicyManager->verifyScopes($this->getClient(), $scopes);
        $this->scopes = $scopes;
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
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 24/05/2018
 * Time: 22:06
 */

namespace OAuth2\Endpoints\Authorization;


use GuzzleHttp\Psr7\Uri;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeInterface;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeManager;
use OAuth2\Exceptions\InvalidAuthorizationRequest;
use OAuth2\Exceptions\InvalidRequestMethod;
use OAuth2\Exceptions\OAuthException;
use OAuth2\ResponseModes\ResponseModeInterface;
use OAuth2\ResponseModes\ResponseModeManager;
use OAuth2\Roles\ClientTypes\ConfidentialClientInterface;
use OAuth2\Roles\ClientTypes\PublicClientInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Roles\ResourceOwnerInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;


class AuthorizationRequestBuilder
{
    /**
     * @var ClientStorageInterface
     */
    protected $clientStorage;
    /**
     * @var ResponseTypeManager
     */
    protected $responseTypeManager;
    /**
     * @var ResponseModeManager
     */
    protected $responseModeManager;
    /**
     * @var ScopePolicyManager
     */
    protected $scopePolicyManager;

    public function __construct(ClientStorageInterface $clientStorage,
                                ResponseTypeManager $responseTypeManager,
                                ResponseModeManager $responseModeManager,
                                ScopePolicyManager $scopePolicyManager)
    {
        $this->clientStorage = $clientStorage;
        $this->responseTypeManager = $responseTypeManager;
        $this->responseModeManager = $responseModeManager;
        $this->scopePolicyManager = $scopePolicyManager;
    }

    /**
     * @param ServerRequestInterface $request
     * @param ResourceOwnerInterface $resourceOwner
     * @return AuthorizationRequest
     * @throws InvalidRequestMethod
     * @throws OAuthException
     * @throws InvalidAuthorizationRequest
     */
    public function build(ServerRequestInterface $request, ResourceOwnerInterface $resourceOwner): AuthorizationRequest
    {
        if ($request->getMethod() === 'GET') {
            $data = $request->getQueryParams();
        } else if ($request->getMethod() === 'POST') {
            $data = is_array($request->getParsedBody()) ? $request->getParsedBody() : [];
        } else {
            throw new InvalidRequestMethod();
        }

        $client = $this->getClient($data['client_id'] ?? null);
        $responseType = $this->getResponseType($client, $data['response_type'] ?? null);
        $redirectUri = $this->getRedirectUri($client, $responseType, $data['redirect_uri'] ?? null);
        $responseMode = $this->getResponseMode($responseType, $data['response_mode'] ?? null);
        $state = $requestData['state'] ?? null;

        try {
            $requestedScopes = $this->scopePolicyManager->scopeStringToArray($data['scope'] ?? null);
            $scopes = $this->scopePolicyManager->getScopes($client, $requestedScopes);
        } catch (OAuthException $e) {
            throw new InvalidAuthorizationRequest($e, $redirectUri, $responseMode, $state);
        }

        return new AuthorizationRequest($data, $resourceOwner, $client, $redirectUri, $responseType, $responseMode,
            $scopes, $requestedScopes, $state);
    }

    /**
     * @param null|string $clientIdentifier
     * @return RegisteredClient
     * @throws OAuthException
     */
    protected function getClient(?string $clientIdentifier): RegisteredClient
    {
        if (empty($clientIdentifier)) {
            throw new OAuthException('invalid_request', 'The request is missing the required parameter client_id.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if (!($client = $this->clientStorage->get($clientIdentifier))) {
            throw new OAuthException('invalid_request', 'The request includes the invalid parameter client_id.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        return $client;
    }

    protected function isRedirectUriRegistrationRequired(RegisteredClient $client, ResponseTypeInterface $responseType)
    {
        if ($client instanceof PublicClientInterface ||
            ($client instanceof ConfidentialClientInterface && $responseType->isRegistrationOfRedirectUriRequired())) {
            return true;
        }
        return false;
    }

    /**
     * @param RegisteredClient $client
     * @param ResponseTypeInterface $responseType
     * @return array|null
     * @throws OAuthException
     */
    protected function getRegisteredRedirectUris(RegisteredClient $client, ResponseTypeInterface $responseType)
    {
        $redirectUris = $client->getMetadata()->getRedirectUris();

        if (empty($redirectUris) && $this->isRedirectUriRegistrationRequired($client, $responseType)) {
            throw new OAuthException('invalid_request',
                'Clients using flows with redirection MUST register their redirection URI values',
                'https://tools.ietf.org/html/rfc7591#section-2.1');
        }

        return $redirectUris;
    }

    /**
     * @param RegisteredClient $client
     * @param ResponseTypeInterface $responseType
     * @param null|string $requestRedirectUri
     * @return Uri
     * @throws OAuthException
     */
    protected function getRedirectUri(RegisteredClient $client, ResponseTypeInterface $responseType,
                                      ?string $requestRedirectUri = null)
    {
        $registeredRedirectUris = $this->getRegisteredRedirectUris($client, $responseType);

        if (!$requestRedirectUri) {
            if (count($registeredRedirectUris) != 1) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter redirect_uri.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }

            $requestRedirectUri = $registeredRedirectUris[0];
        } else if (!empty($registeredRedirectUris) && !in_array($requestRedirectUri, $registeredRedirectUris)) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter redirect_uri.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        try {
            $redirectUri = new Uri($requestRedirectUri);
            if ($redirectUri->getFragment()) {
                throw new \InvalidArgumentException('The endpoint URI must not include a fragment component.');
            }
        } catch (\InvalidArgumentException $e) {
            throw new OAuthException('invalid_request',
                'The request includes the malformed parameter redirect_uri. ' . $e->getMessage(),
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        return $redirectUri;
    }

    /**
     * @param RegisteredClient $client
     * @param null|string $requestResponseType
     * @return ResponseTypeInterface
     * @throws OAuthException
     */
    protected function getResponseType(RegisteredClient $client, ?string $requestResponseType = null): ResponseTypeInterface
    {
        if (empty($requestResponseType)) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter response_type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if (!($responseType = $this->responseTypeManager->getResponseType($requestResponseType))) {
            throw new OAuthException('invalid_request',
                'The request includes the invalid parameter response_type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        $supportedResponseTypes = $client->getMetadata()->getResponseTypes() ?: ['code'];
        foreach (explode(' ', $requestResponseType) as $type) {
            if (!in_array($type, $supportedResponseTypes)) {
                throw new OAuthException('unsupported_response_type',
                    'The authorization server does not support obtaining an authorization code using this method.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }
        }

        return $responseType;
    }

    /**
     * @param ResponseTypeInterface $responseType
     * @param null|string $requestResponseMode
     * @return ResponseModeInterface
     * @throws OAuthException
     */
    protected function getResponseMode(ResponseTypeInterface $responseType, ?string $requestResponseMode = null): ResponseModeInterface
    {
        $responseModeIdentifier = $responseType->getDefaultResponseMode();
        if (!empty($requestResponseMode)) {
            $responseModeIdentifier = $requestResponseMode;
        }

        if (!($responseMode = $this->responseModeManager->getResponseMode($responseModeIdentifier))) {
            throw new OAuthException('invalid_request', 'response_mode invalid');
        }

        if (in_array($responseModeIdentifier, $responseType->getUnsupportedResponseModes())) {
            throw new OAuthException('invalid_request', 'response_mode unsupported');
        }

        return $responseMode;
    }
}
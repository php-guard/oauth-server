<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 20/05/2018
 * Time: 19:49
 */

namespace OAuth2\Endpoints\Authorization;


use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeInterface;


use OAuth2\ResponseModes\ResponseModeInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Roles\ResourceOwnerInterface;


use Psr\Http\Message\UriInterface;

/**
 * Class AuthorizationRequest
 * @package OAuth2\Endpoints
 */
class AuthorizationRequest implements AuthorizationRequestInterface
{
    /**
     * @var array
     */
    protected $data;
    /**
     * @var RegisteredClient
     */
    protected $client;
    /**
     * @var UriInterface
     */
    private $redirectUri;
    /**
     * @var ResponseTypeInterface
     */
    private $responseType;
    /**
     * @var ResponseModeInterface
     */
    private $responseMode;
    /**
     * @var array
     */
    private $scopes;
    /**
     * @var null|string
     */
    private $state;
    /**
     * @var ResourceOwnerInterface
     */
    private $resourceOwner;
    /**
     * @var array|null
     */
    private $requestedScopes;

    /**
     * AuthorizationRequest constructor.
     * @param array $data
     * @param ResourceOwnerInterface $resourceOwner
     * @param RegisteredClient $client
     * @param UriInterface $redirectUri
     * @param ResponseTypeInterface $responseType
     * @param ResponseModeInterface $responseMode
     * @param array $scopes
     * @param array|null $requestedScopes
     * @param null|string $state
     */
    public function __construct(array $data, ResourceOwnerInterface $resourceOwner,
                                RegisteredClient $client, UriInterface $redirectUri,
                                ResponseTypeInterface $responseType, ResponseModeInterface $responseMode,
                                array $scopes, ?array $requestedScopes, ?string $state)
    {
        $this->data = $data;
        $this->resourceOwner = $resourceOwner;
        $this->client = $client;
        $this->redirectUri = $redirectUri;
        $this->responseType = $responseType;
        $this->responseMode = $responseMode;
        $this->scopes = $scopes;
        $this->state = $state;
        $this->requestedScopes = $requestedScopes;
    }

    public function getData(): array
    {
        return $this->data;
    }

    /**
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        return $this->resourceOwner;
    }


    /**
     * @return RegisteredClient
     */
    public function getClient(): RegisteredClient
    {
        return $this->client;
    }

    /**
     * @return UriInterface
     */
    public function getRedirectUri(): UriInterface
    {
        return $this->redirectUri;
    }

    /**
     * @return ResponseTypeInterface
     */
    public function getResponseType(): ResponseTypeInterface
    {
        return $this->responseType;
    }

    /**
     * @return ResponseModeInterface
     */
    public function getResponseMode(): ResponseModeInterface
    {
        return $this->responseMode;
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return array|null
     */
    public function getRequestedScopes(): ?array
    {
        return $this->requestedScopes;
    }

    /**
     * @return null|string
     */
    public function getState(): ?string
    {
        return $this->state;
    }
}
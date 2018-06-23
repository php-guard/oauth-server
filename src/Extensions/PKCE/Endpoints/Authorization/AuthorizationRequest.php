<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 21:05
 */

namespace OAuth2\Extensions\PKCE\Endpoints\Authorization;


use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeInterface;
use OAuth2\Endpoints\Authorization\AuthorizationRequestInterface;
use OAuth2\ResponseModes\ResponseModeInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Roles\ResourceOwnerInterface;
use Psr\Http\Message\UriInterface;

class AuthorizationRequest implements AuthorizationRequestInterface
{
    /**
     * @var string
     */
    private $codeChallenge;
    /**
     * @var string
     */
    private $codeChallengeMethod;
    /**
     * @var \OAuth2\Endpoints\Authorization\AuthorizationRequest
     */
    private $authorizationRequest;

    /** @noinspection PhpMissingParentConstructorInspection
     * @param \OAuth2\Endpoints\Authorization\AuthorizationRequest $authorizationRequest
     * @param string $codeChallenge
     * @param string $codeChallengeMethod
     */
    public function __construct(\OAuth2\Endpoints\Authorization\AuthorizationRequest $authorizationRequest,
                                string $codeChallenge, string $codeChallengeMethod = 'plain')
    {
        $this->authorizationRequest = $authorizationRequest;
        $this->codeChallenge = $codeChallenge;
        $this->codeChallengeMethod = $codeChallengeMethod;
    }


    public function __call($name, $args) {
        $this->authorizationRequest->$name($args);
    }

    /**
     * @return string
     */
    public function getCodeChallenge(): string
    {
        return $this->codeChallenge;
    }

    /**
     * @return string
     */
    public function getCodeChallengeMethod(): string
    {
        return $this->codeChallengeMethod;
    }

    public function getData(): array
    {
       return $this->authorizationRequest->getData();
    }

    /**
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(): ResourceOwnerInterface
    {
        return $this->authorizationRequest->getResourceOwner();
    }

    /**
     * @return RegisteredClient
     */
    public function getClient(): RegisteredClient
    {
        return $this->authorizationRequest->getClient();
    }

    /**
     * @return UriInterface
     */
    public function getRedirectUri(): UriInterface
    {
        return $this->authorizationRequest->getRedirectUri();
    }

    /**
     * @return ResponseTypeInterface
     */
    public function getResponseType(): ResponseTypeInterface
    {
        return $this->authorizationRequest->getResponseType();
    }

    /**
     * @return ResponseModeInterface
     */
    public function getResponseMode(): ResponseModeInterface
    {
        return $this->authorizationRequest->getResponseMode();
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->authorizationRequest->getScopes();
    }

    /**
     * @return array|null
     */
    public function getRequestedScopes(): ?array
    {
        return $this->authorizationRequest->getRequestedScopes();
    }

    /**
     * @return null|string
     */
    public function getState(): ?string
    {
        return $this->authorizationRequest->getState();
    }
}
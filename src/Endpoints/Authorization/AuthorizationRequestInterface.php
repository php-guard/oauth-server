<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 23/06/2018
 * Time: 23:27
 */

namespace OAuth2\Endpoints\Authorization;


use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeInterface;
use OAuth2\ResponseModes\ResponseModeInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Roles\ResourceOwnerInterface;
use Psr\Http\Message\UriInterface;

interface AuthorizationRequestInterface
{
    public function getData(): array;

    /**
     * @return ResourceOwnerInterface
     */
    public function getResourceOwner(): ResourceOwnerInterface;


    /**
     * @return RegisteredClient
     */
    public function getClient(): RegisteredClient;

    /**
     * @return UriInterface
     */
    public function getRedirectUri(): UriInterface;

    /**
     * @return ResponseTypeInterface
     */
    public function getResponseType(): ResponseTypeInterface;

    /**
     * @return ResponseModeInterface
     */
    public function getResponseMode(): ResponseModeInterface;

    /**
     * @return array
     */
    public function getScopes(): array;

    /**
     * @return array|null
     */
    public function getRequestedScopes(): ?array;

    /**
     * @return null|string
     */
    public function getState(): ?string;
}
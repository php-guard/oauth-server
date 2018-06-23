<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 19:12
 */

namespace OAuth2\AuthorizationEndpointResponseTypes;


class ResponseTypeManager
{
    protected $responseTypes = [];

    public function setResponseType(string $identifier, ResponseTypeInterface $responseType): self
    {
        $this->responseTypes[$identifier] = $responseType;
        return $this;
    }

    public function getResponseType(string $identifier): ?ResponseTypeInterface
    {
        return $this->responseTypes[$identifier] ?? null;
    }
}
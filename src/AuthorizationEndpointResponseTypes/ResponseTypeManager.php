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

    public function addResponseType(string $identifier, ResponseTypeInterface $responseType)
    {
        $this->responseTypes[$identifier] = $responseType;
    }

    public function getResponseType(string $identifier): ?ResponseTypeInterface
    {
        return $this->responseTypes[$identifier] ?? null;
    }
}
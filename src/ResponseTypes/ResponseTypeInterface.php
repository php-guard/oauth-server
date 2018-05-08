<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 19:12
 */

namespace OAuth2\ResponseTypes;


use OAuth2\Endpoints\AuthorizationEndpoint;

interface ResponseTypeInterface
{
    function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData);

    function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array;

    function getDefaultResponseMode(): string;

    function getUnsupportedResponseModes(): array;
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 22:20
 */

namespace OAuth2\AuthorizationGrantTypes;


use OAuth2\Endpoints\TokenEndpoint;

interface GrantTypeInterface
{
    function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array;
}
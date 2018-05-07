<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:34
 */

namespace OAuth2\ResponseModes;


use OAuth2\Endpoints\AuthorizationEndpoint;
use Psr\Http\Message\ResponseInterface;

interface ResponseModeInterface
{
    function buildResponse(AuthorizationEndpoint $authorizationEndpoint, array $requestData, array $responseData): ResponseInterface;
}
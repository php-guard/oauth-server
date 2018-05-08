<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 19:06
 */

namespace OAuth2\ResponseModes;


use GuzzleHttp\Psr7\Response;
use OAuth2\Endpoints\AuthorizationEndpoint;
use Psr\Http\Message\ResponseInterface;

class QueryResponseMode implements ResponseModeInterface
{
    public function buildResponse(AuthorizationEndpoint $authorizationEndpoint, array $requestData, array $responseData): ResponseInterface
    {
        $uri = $authorizationEndpoint->getRedirectUri();
        $uri = $uri->withQuery(http_build_query($responseData));

        return new Response(302, ['Location' => $uri->__toString()]);
    }
}
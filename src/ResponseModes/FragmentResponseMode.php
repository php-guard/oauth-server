<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 23:27
 */

namespace OAuth2\ResponseModes;


use GuzzleHttp\Psr7\Response;
use OAuth2\Endpoints\AuthorizationEndpoint;
use Psr\Http\Message\ResponseInterface;

class FragmentResponseMode implements ResponseModeInterface
{
    public function buildResponse(AuthorizationEndpoint $authorizationEndpoint, array $requestData, array $responseData): ResponseInterface
    {
        $uri = $authorizationEndpoint->getRedirectUri();
        $uri = $uri->withFragment(http_build_query($responseData));

        return new Response(302, ['Location' => $uri->__toString()]);
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 19:06
 */

namespace OAuth2\ResponseModes;


use GuzzleHttp\Psr7\Response;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class QueryResponseMode implements ResponseModeInterface
{
    public function buildResponse(UriInterface $redirectUri, array $responseData): ResponseInterface
    {
        $uri = $redirectUri->withQuery(http_build_query($responseData));
        return new Response(302, ['Location' => $uri->__toString()]);
    }
}
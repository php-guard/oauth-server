<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 23:27
 */

namespace OAuth2\ResponseModes;


use GuzzleHttp\Psr7\Response;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

class FragmentResponseMode implements ResponseModeInterface
{
    public function buildResponse(UriInterface $redirectUri, array $responseData): ResponseInterface
    {
        $uri = $redirectUri->withFragment(http_build_query($responseData));
        return new Response(302, ['Location' => $uri->__toString()]);
    }
}
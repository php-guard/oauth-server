<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:34
 */

namespace OAuth2\ResponseModes;



use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;

interface ResponseModeInterface
{
public function buildResponse(UriInterface $redirectUri, array $responseData): ResponseInterface;
}
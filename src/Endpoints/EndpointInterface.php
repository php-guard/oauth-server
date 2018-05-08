<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:13
 */

namespace OAuth2\Endpoints;


use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

interface EndpointInterface
{
    function handleRequest(ServerRequestInterface $request): ResponseInterface;
}
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

/**
 * Interface EndpointInterface
 * @package OAuth2\Endpoints
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3
 * The authorization process utilizes two authorization server endpoints
 * (HTTP resources):
 *
 * o  Authorization endpoint - used by the client to obtain
 * authorization from the resource owner via user-agent redirection.
 *
 * o  Token endpoint - used by the client to exchange an authorization
 * grant for an access token, typically with client authentication.
 *
 * As well as one client endpoint:
 *
 * o  Redirection endpoint - used by the authorization server to return
 * responses containing authorization credentials to the client via
 * the resource owner user-agent.
 *
 * Not every authorization grant type utilizes both endpoints.
 * Extension grant types MAY define additional endpoints as needed.
 */
interface EndpointInterface
{
public function handleRequest(ServerRequestInterface $request): ResponseInterface;
}
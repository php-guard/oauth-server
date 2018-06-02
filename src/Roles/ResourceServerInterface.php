<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 11/01/2018
 * Time: 14:22
 */

namespace OAuth2\Roles;

use OAuth2\Roles\ResourceServer\AuthenticatedRequest;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Interface ResourceServerInterface
 * @package OAuth2\Roles
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.1
 * The server hosting the protected resources, capable of accepting
 * and responding to protected resource requests using access tokens.
 */
interface ResourceServerInterface
{
    public function verifyRequest(ServerRequestInterface $request, array $requiredScopes, ?string $realm = null): ?ResponseInterface;
}
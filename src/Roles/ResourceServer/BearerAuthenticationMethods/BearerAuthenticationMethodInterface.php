<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 27/05/2018
 * Time: 17:53
 */

namespace OAuth2\Roles\ResourceServer\BearerAuthenticationMethods;

use Psr\Http\Message\ServerRequestInterface;

interface BearerAuthenticationMethodInterface
{
    public function support(ServerRequestInterface $request): bool;

    public function authenticate(ServerRequestInterface $request): ?string;
}
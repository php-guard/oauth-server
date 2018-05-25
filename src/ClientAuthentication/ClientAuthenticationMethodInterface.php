<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 16:57
 */

namespace OAuth2\ClientAuthentication;

use OAuth2\Roles\ClientInterface;
use Psr\Http\Message\ServerRequestInterface;

interface ClientAuthenticationMethodInterface
{
public function support(ServerRequestInterface $request, array $requestData): bool;

public function authenticate(ServerRequestInterface $request, array $requestData): ?ClientInterface;
}
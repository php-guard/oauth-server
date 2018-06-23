<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 02/06/2018
 * Time: 18:13
 */

namespace OAuth2\Roles;

use OAuth2\Endpoints\EndpointInterface;

/**
 * Class AuthorizationServerInterface
 * @package OAuth2\Roles
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.1
 * The server issuing access tokens to the client after successfully
 * authenticating the resource owner and obtaining authorization.
 */
interface AuthorizationServerInterface
{
    public function getAuthorizationEndpoint(): EndpointInterface;

    public function getTokenEndpoint(): EndpointInterface;
}
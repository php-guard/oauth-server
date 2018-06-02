<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 21:28
 */

namespace OAuth2\Roles;



use OAuth2\Endpoints\AuthorizationRequest;
use Psr\Http\Message\ResponseInterface;

/**
 * Interface ResourceOwnerInterface
 * @package OAuth2\Roles
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.1
 * An entity capable of granting access to a protected resource.
 * When the resource owner is a person, it is referred to as an
 * end-user.
 */
interface ResourceOwnerInterface
{
    public function getIdentifier(): string;
}
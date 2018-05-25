<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeInterface;
use OAuth2\AuthorizationGrantTypes\GrantTypeInterface;

/**
 * Interface FlowInterface
 * @package OAuth2\AuthorizationGrantTypes\Flows
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3
 * An authorization grant is a credential representing the resource
 * owner's authorization (to access its protected resources) used by the
 * client to obtain an access token.  This specification defines four
 * grant types -- authorization code, implicit, resource owner password
 * credentials, and client credentials -- as well as an extensibility
 * mechanism for defining additional types.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4
 * To request an access token, the client obtains authorization from the
 * resource owner.  The authorization is expressed in the form of an
 * authorization grant, which the client uses to request the access
 * token.  OAuth defines four grant types: authorization code, implicit,
 * resource owner password credentials, and client credentials.  It also
 * provides an extension mechanism for defining additional grant types.
 */
interface FlowInterface extends ResponseTypeInterface, GrantTypeInterface
{
    /**
     * @return string[]
     */
    public function getResponseTypes(): array;

    /**
     * @return string[]
     */
    public function getGrantTypes(): array;
}
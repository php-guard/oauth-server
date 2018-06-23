<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 25/05/2018
 * Time: 23:23
 */

namespace OAuth2\Roles\ClientTypes;


use OAuth2\Roles\ClientInterface;

interface RegisteredClientInterface extends ClientInterface
{
    /**
     * @return string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-2.2
     * The authorization server issues the registered client a client
     * identifier -- a unique string representing the registration
     * information provided by the client.  The client identifier is not a
     * secret; it is exposed to the resource owner and MUST NOT be used
     * alone for client authentication.  The client identifier is unique to
     * the authorization server.
     *
     * The client identifier string size is left undefined by this
     * specification.  The client should avoid making assumptions about the
     * identifier size.  The authorization server SHOULD document the size
     * of any identifier it issues.
     */
    public function getIdentifier(): string;
}
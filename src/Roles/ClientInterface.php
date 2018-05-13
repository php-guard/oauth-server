<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 21:30
 */

namespace OAuth2\Roles;


use OAuth2\Roles\ClientTypes\ClientMetadataInterface;

/**
 * Interface ClientInterface
 * @package OAuth2\Roles
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.1
 * An application making protected resource requests on behalf of the
 * resource owner and with its authorization.  The term "client" does
 * not imply any particular implementation characteristics (e.g.,
 * whether the application executes on a server, a desktop, or other
 * devices).
 */
interface ClientInterface
{
//    function getIdentifier(): string;
//
//    function getPassword(): ?string;

    /**
     * @return bool
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.2.1
     * Confidential clients or other clients issued client credentials MUST
     * authenticate with the authorization server as described in
     * Section 2.3 when making requests to the token endpoint.
     */
    function hasCredentials(): bool;

//    function isHttpBasicAuthenticationSchemeSupported(): bool;

//    function isTLSSupported(): bool;

    function getMetadata(): ClientMetadataInterface;
}
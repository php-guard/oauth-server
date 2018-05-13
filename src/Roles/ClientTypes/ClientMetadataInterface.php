<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 15/03/2018
 * Time: 23:12
 */

namespace OAuth2\Roles\ClientTypes;


interface ClientMetadataInterface
{
    /**
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2
     * After completing its interaction with the resource owner, the
     * authorization server directs the resource owner's user-agent back to
     * the client.  The authorization server redirects the user-agent to the
     * client's redirection endpoint previously established with the
     * authorization server during the client registration process or when
     * making the authorization request.
     *
     * The redirection endpoint URI MUST be an absolute URI as defined by
     * [RFC3986] Section 4.3.  The endpoint URI MAY include an
     * "application/x-www-form-urlencoded" formatted (per Appendix B) query
     * component ([RFC3986] Section 3.4), which MUST be retained when adding
     * additional query parameters.  The endpoint URI MUST NOT include a
     * fragment component.
     *
     * @return array|null
     */
    function getRedirectUris(): ?array;

    /**
     * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
     * Including the client credentials in the request-body using the two
     * parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
     * to directly utilize the HTTP Basic authentication scheme (or other
     * password-based HTTP authentication schemes).  The parameters can only
     * be transmitted in the request-body and MUST NOT be included in the
     * request URI.
     *
     * @return null|string
     */
    function getTokenEndpointAuthMethod(): ?string;

    /**
     * @return array|null
     */
    function getGrantTypes(): ?array;

    /**
     * @return array|null
     */
    function getResponseTypes(): ?array;

    /**
     * @return null|string
     */
    function getClientName(): ?string;

    /**
     * @return null|string
     */
    function getClientUri(): ?string;

    /**
     * @return null|string
     */
    function getLogoUri(): ?string;

    /**
     * @return null|string[]
     */
    function getScopes(): ?array;

    /**
     * @return array|null
     */
    function getContacts(): ?array;

    /**
     * @return null|string
     */
    function getTosUri(): ?string;

    /**
     * @return null|string
     */
    function getPolicyUri(): ?string;

    /**
     * @return null|string
     */
    function getJwksUri(): ?string;

    /**
     * @return array|null
     */
    function getJwks(): ?array;

    /**
     * @return null|string
     */
    function getSoftwareId(): ?string;

    /**
     * @return null|string
     */
    function getSoftwareVersion(): ?string;
}
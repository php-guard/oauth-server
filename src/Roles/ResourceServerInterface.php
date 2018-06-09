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
    /**
     * @param ServerRequestInterface $request
     * @param null|string $realm
     * @param null|string $scope
     * @return null|ResponseInterface
     *
     * @see https://tools.ietf.org/html/rfc6750#section-3
     * All challenges defined by this specification MUST use the auth-scheme
     * value "Bearer".  This scheme MUST be followed by one or more
     * auth-param values.  The auth-param attributes used or defined by this
     * specification are as follows.  Other auth-param attributes MAY be
     * used as well.
     *
     * A "realm" attribute MAY be included to indicate the scope of
     * protection in the manner described in HTTP/1.1 [RFC2617].  The
     * "realm" attribute MUST NOT appear more than once.
     *
     * The "scope" attribute is defined in Section 3.3 of [RFC6749].  The
     * "scope" attribute is a space-delimited list of case-sensitive scope
     * values indicating the required scope of the access token for
     * accessing the requested resource. "scope" values are implementation
     * defined; there is no centralized registry for them; allowed values
     * are defined by the authorization server.  The order of "scope" values
     * is not significant.  In some cases, the "scope" value will be used
     * when requesting a new access token with sufficient scope of access to
     * utilize the protected resource.  Use of the "scope" attribute is
     * OPTIONAL.  The "scope" attribute MUST NOT appear more than once.  The
     * "scope" value is intended for programmatic use and is not meant to be
     * displayed to end-users.
     */
    public function verifyRequest(ServerRequestInterface $request,  ?string $realm = null, ?string $scope = null): ?ResponseInterface;
}
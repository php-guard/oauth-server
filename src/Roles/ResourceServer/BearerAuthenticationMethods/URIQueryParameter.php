<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 09/06/2018
 * Time: 18:47
 */

namespace OAuth2\Roles\ResourceServer\BearerAuthenticationMethods;


use Psr\Http\Message\ServerRequestInterface;

/**
 * Class URIQueryParameter
 * @package OAuth2\Roles\ResourceServer\BearerAuthenticationMethods
 *
 * @see https://tools.ietf.org/html/rfc6750#section-2.3
 * When sending the access token in the HTTP request URI, the client
 * adds the access token to the request URI query component as defined
 * by "Uniform Resource Identifier (URI): Generic Syntax" [RFC3986],
 * using the "access_token" parameter.
 *
 * For example, the client makes the following HTTP request using
 * transport-layer security:
 *
 * GET /resource?access_token=mF_9.B5f-4.1JqM HTTP/1.1
 * Host: server.example.com
 *
 * The HTTP request URI query can include other request-specific
 * parameters, in which case the "access_token" parameter MUST be
 * properly separated from the request-specific parameters using "&"
 * character(s) (ASCII code 38).
 *
 * For example:
 *
 * https://server.example.com/resource?access_token=mF_9.B5f-4.1JqM&p=q
 *
 * Clients using the URI Query Parameter method SHOULD also send a
 * Cache-Control header containing the "no-store" option.  Server
 * success (2XX status) responses to these requests SHOULD contain a
 * Cache-Control header with the "private" option.
 *
 * Because of the security weaknesses associated with the URI method
 * (see Section 5), including the high likelihood that the URL
 * containing the access token will be logged, it SHOULD NOT be used
 * unless it is impossible to transport the access token in the
 * "Authorization" request header field or the HTTP request entity-body.
 * Resource servers MAY support this method.
 *
 * This method is included to document current use; its use is not
 * recommended, due to its security deficiencies (see Section 5) and
 * also because it uses a reserved query parameter name, which is
 * counter to URI namespace best practices, per "Architecture of the
 * World Wide Web, Volume One" [W3C.REC-webarch-20041215].
 */
class URIQueryParameter implements BearerAuthenticationMethodInterface
{

    public function support(ServerRequestInterface $request): bool
    {
        return isset($request->getQueryParams()['access_token']);
    }

    public function authenticate(ServerRequestInterface $request): ?string
    {
        return $request->getQueryParams()['access_token'] ?? null;
    }
}
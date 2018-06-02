<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 27/05/2018
 * Time: 17:53
 */

namespace OAuth2\Roles\ResourceServer\BearerAuthenticationMethods;


use Psr\Http\Message\ServerRequestInterface;
use Symfony\Component\VarDumper\VarDumper;


/**
 * Class AuthorizationRequestHeaderField
 * @package OAuth2\Roles\ResourceServer\BearerAuthenticationMethods
 *
 * @see https://tools.ietf.org/html/rfc6750#section-2.1
 * When sending the access token in the "Authorization" request header
 * field defined by HTTP/1.1 [RFC2617], the client uses the "Bearer"
 * authentication scheme to transmit the access token.
 *
 * For example:
 *
 * GET /resource HTTP/1.1
 * Host: server.example.com
 * Authorization: Bearer mF_9.B5f-4.1JqM
 *
 * The syntax of the "Authorization" header field for this scheme
 * follows the usage of the Basic scheme defined in Section 2 of
 * [RFC2617].  Note that, as with Basic, it does not conform to the
 * generic syntax defined in Section 1.2 of [RFC2617] but is compatible
 * with the general authentication framework being developed for
 * HTTP 1.1 [HTTP-AUTH], although it does not follow the preferred
 * practice outlined therein in order to reflect existing deployments.
 * The syntax for Bearer credentials is as follows:
 *
 * b64token    = 1*( ALPHA / DIGIT /
 * "-" / "." / "_" / "~" / "+" / "/" ) *"="
 * credentials = "Bearer" 1*SP b64token
 *
 * Clients SHOULD make authenticated requests with a bearer token using
 * the "Authorization" request header field with the "Bearer" HTTP
 * authorization scheme.  Resource servers MUST support this method.
 */
class AuthorizationRequestHeaderField implements BearerAuthenticationMethodInterface
{

    public function support(ServerRequestInterface $request): bool
    {
        return $request->hasHeader('Authorization');
    }

    public function authenticate(ServerRequestInterface $request): ?string
    {
        $authorizationHeader = $request->getHeader('Authorization');
        if (!empty($authorizationHeader)) {
            if (preg_match('/Bearer\s(\S+)/', $authorizationHeader[0], $matches)) {
                return $matches[1];
            }
        }
        return null;
    }
}
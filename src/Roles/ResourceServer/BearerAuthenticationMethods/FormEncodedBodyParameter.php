<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 27/05/2018
 * Time: 18:13
 */

namespace OAuth2\Roles\ResourceServer\BearerAuthenticationMethods;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class FormEncodedBodyParameter
 * @package OAuth2\Roles\ResourceServer\BearerAuthenticationMethods
 *
 * @see https://tools.ietf.org/html/rfc6750#section-2.2
 * When sending the access token in the HTTP request entity-body, the
 * client adds the access token to the request-body using the
 * "access_token" parameter.  The client MUST NOT use this method unless
 * all of the following conditions are met:
 *
 * o  The HTTP request entity-header includes the "Content-Type" header
 * field set to "application/x-www-form-urlencoded".
 *
 * o  The entity-body follows the encoding requirements of the
 * "application/x-www-form-urlencoded" content-type as defined by
 * HTML 4.01 [W3C.REC-html401-19991224].
 *
 * o  The HTTP request entity-body is single-part.
 *
 * o  The content to be encoded in the entity-body MUST consist entirely
 * of ASCII [USASCII] characters.
 *
 * o  The HTTP request method is one for which the request-body has
 * defined semantics.  In particular, this means that the "GET"
 * method MUST NOT be used.
 *
 * The entity-body MAY include other request-specific parameters, in
 * which case the "access_token" parameter MUST be properly separated
 * from the request-specific parameters using "&" character(s) (ASCII
 * code 38).
 *
 * For example, the client makes the following HTTP request using
 * transport-layer security:
 *
 * POST /resource HTTP/1.1
 * Host: server.example.com
 * Content-Type: application/x-www-form-urlencoded
 *
 * access_token=mF_9.B5f-4.1JqM
 *
 * The "application/x-www-form-urlencoded" method SHOULD NOT be used
 * except in application contexts where participating browsers do not
 * have access to the "Authorization" request header field.  Resource
 * servers MAY support this method.
 */
class FormEncodedBodyParameter implements BearerAuthenticationMethodInterface
{
    public function support(ServerRequestInterface $request): bool
    {

    }

    public function authenticate(ServerRequestInterface $request): ?string
    {

    }
}
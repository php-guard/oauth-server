<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 22:20
 */

namespace OAuth2\AuthorizationGrantTypes;


use OAuth2\Endpoints\TokenEndpoint;

interface GrantTypeInterface
{
    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5
     * If the access token request is valid and authorized, the
     * authorization server issues an access token and optional refresh
     * token as described in Section 5.1.  If the request failed client
     * authentication or is invalid, the authorization server returns an
     * error response as described in Section 5.2.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.1
     * The authorization server issues an access token and optional refresh
     * token, and constructs the response by adding the following parameters
     * to the entity-body of the HTTP response with a 200 (OK) status code:
     *
     * access_token
     * REQUIRED.  The access token issued by the authorization server.
     *
     * token_type
     * REQUIRED.  The type of the token issued as described in
     * Section 7.1.  Value is case insensitive.
     *
     * expires_in
     * RECOMMENDED.  The lifetime in seconds of the access token.  For
     * example, the value "3600" denotes that the access token will
     * expire in one hour from the time the response was generated.
     * If omitted, the authorization server SHOULD provide the
     * expiration time via other means or document the default value.
     *
     * refresh_token
     * OPTIONAL.  The refresh token, which can be used to obtain new
     * access tokens using the same authorization grant as described
     * in Section 6.
     *
     * scope
     * OPTIONAL, if identical to the scope requested by the client;
     * otherwise, REQUIRED.  The scope of the access token as
     * described by Section 3.3.
     *
     * The parameters are included in the entity-body of the HTTP response
     * using the "application/json" media type as defined by [RFC4627].  The
     * parameters are serialized into a JavaScript Object Notation (JSON)
     * structure by adding each parameter at the highest structure level.
     * Parameter names and string values are included as JSON strings.
     * Numerical values are included as JSON numbers.  The order of
     * parameters does not matter and can vary.
     *
     * The authorization server MUST include the HTTP "Cache-Control"
     * response header field [RFC2616] with a value of "no-store" in any
     * response containing tokens, credentials, or other sensitive
     * information, as well as the "Pragma" response header field [RFC2616]
     * with a value of "no-cache".
     *
     * For example:
     *
     * HTTP/1.1 200 OK
     * Content-Type: application/json;charset=UTF-8
     * Cache-Control: no-store
     * Pragma: no-cache
     *
     * {
     * "access_token":"2YotnFZFEjr1zCsicMWpAA",
     * "token_type":"example",
     * "expires_in":3600,
     * "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
     * "example_parameter":"example_value"
     * }
     *
     * The client MUST ignore unrecognized value names in the response.  The
     * sizes of tokens and other values received from the authorization
     * server are left undefined.  The client should avoid making
     * assumptions about value sizes.  The authorization server SHOULD
     * document the size of any value it issues.
     *
     * @see https://tools.ietf.org/html/rfc6749#section-5.2
     * The authorization server responds with an HTTP 400 (Bad Request)
     * status code (unless specified otherwise) and includes the following
     * parameters with the response:
     *
     * error
     * REQUIRED.  A single ASCII [USASCII] error code from the
     * following:
     *
     * invalid_request
     * The request is missing a required parameter, includes an
     * unsupported parameter value (other than grant type),
     * repeats a parameter, includes multiple credentials,
     * utilizes more than one mechanism for authenticating the
     * client, or is otherwise malformed.
     *
     * invalid_client
     * Client authentication failed (e.g., unknown client, no
     * client authentication included, or unsupported
     * authentication method).  The authorization server MAY
     * return an HTTP 401 (Unauthorized) status code to indicate
     * which HTTP authentication schemes are supported.  If the
     * client attempted to authenticate via the "Authorization"
     * request header field, the authorization server MUST
     * respond with an HTTP 401 (Unauthorized) status code and
     * include the "WWW-Authenticate" response header field
     * matching the authentication scheme used by the client.
     *
     * invalid_grant
     * The provided authorization grant (e.g., authorization
     * code, resource owner credentials) or refresh token is
     * invalid, expired, revoked, does not match the redirection
     * URI used in the authorization request, or was issued to
     * another client.
     *
     * unauthorized_client
     * The authenticated client is not authorized to use this
     * authorization grant type.
     *
     * unsupported_grant_type
     * The authorization grant type is not supported by the
     * authorization server.
     *
     * invalid_scope
     * The requested scope is invalid, unknown, malformed, or
     * exceeds the scope granted by the resource owner.
     *
     * Values for the "error" parameter MUST NOT include characters
     * outside the set %x20-21 / %x23-5B / %x5D-7E.
     *
     * error_description
     * OPTIONAL.  Human-readable ASCII [USASCII] text providing
     * additional information, used to assist the client developer in
     * understanding the error that occurred.
     * Values for the "error_description" parameter MUST NOT include
     * characters outside the set %x20-21 / %x23-5B / %x5D-7E.
     *
     * error_uri
     * OPTIONAL.  A URI identifying a human-readable web page with
     * information about the error, used to provide the client
     * developer with additional information about the error.
     * Values for the "error_uri" parameter MUST conform to the
     * URI-reference syntax and thus MUST NOT include characters
     * outside the set %x21 / %x23-5B / %x5D-7E.
     *
     * The parameters are included in the entity-body of the HTTP response
     * using the "application/json" media type as defined by [RFC4627].  The
     * parameters are serialized into a JSON structure by adding each
     * parameter at the highest structure level.  Parameter names and string
     * values are included as JSON strings.  Numerical values are included
     * as JSON numbers.  The order of parameters does not matter and can
     * vary.
     *
     * For example:
     *
     * HTTP/1.1 400 Bad Request
     * Content-Type: application/json;charset=UTF-8
     * Cache-Control: no-store
     * Pragma: no-cache
     *
     * {
     * "error":"invalid_request"
     * }
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array;
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 19:12
 */

namespace OAuth2\AuthorizationEndpointResponseTypes;


use OAuth2\Endpoints\Authorization\AuthorizationRequest;
use OAuth2\Endpoints\Authorization\AuthorizationRequestInterface;
use OAuth2\Endpoints\AuthorizationEndpoint;

/**
 * Interface ResponseTypeInterface
 * @package OAuth2\ResponseTypes
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.1.1
 * The authorization endpoint is used by the authorization code grant
 * type and implicit grant type flows.  The client informs the
 * authorization server of the desired grant type using the following
 * parameter:
 *
 * response_type
 * REQUIRED.  The value MUST be one of "code" for requesting an
 * authorization code as described by Section 4.1.1, "token" for
 * requesting an access token (implicit grant) as described by
 * Section 4.2.1, or a registered extension value as described by
 * Section 8.4.
 *
 * Extension response types MAY contain a space-delimited (%x20) list of
 * values, where the order of values does not matter (e.g., response
 * type "a b" is the same as "b a").  The meaning of such composite
 * response types is defined by their respective specifications.
 *
 * If an authorization request is missing the "response_type" parameter,
 * or if the response type is not understood, the authorization server
 * MUST return an error response as described in Section 4.1.2.1.
 */
interface ResponseTypeInterface
{
    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array $requestData
     * @return mixed
     */
//    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData);

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
     * If the request fails due to a missing, invalid, or mismatching
     * redirection URI, or if the client identifier is missing or invalid,
     * the authorization server SHOULD inform the resource owner of the
     * error and MUST NOT automatically redirect the user-agent to the
     * invalid redirection URI.
     *
     * If the resource owner denies the access request or if the request
     * fails for reasons other than a missing or invalid redirection URI,
     * the authorization server informs the client by adding the following
     * parameters to the query component of the redirection URI using the
     * "application/x-www-form-urlencoded" format, per Appendix B:
     *
     * error
     * REQUIRED.  A single ASCII [USASCII] error code from the
     * following:
     *
     * invalid_request
     * The request is missing a required parameter, includes an
     * invalid parameter value, includes a parameter more than
     * once, or is otherwise malformed.
     *
     * unauthorized_client
     * The client is not authorized to request an authorization
     * code using this method.
     *
     * access_denied
     * The resource owner or authorization server denied the
     * request.
     *
     * unsupported_response_type
     * The authorization server does not support obtaining an
     * authorization code using this method.
     *
     * invalid_scope
     * The requested scope is invalid, unknown, or malformed.
     *
     * server_error
     * The authorization server encountered an unexpected
     * condition that prevented it from fulfilling the request.
     * (This error code is needed because a 500 Internal Server
     * Error HTTP status code cannot be returned to the client
     * via an HTTP redirect.)
     *
     * temporarily_unavailable
     * The authorization server is currently unable to handle
     * the request due to a temporary overloading or maintenance
     * of the server.  (This error code is needed because a 503
     * Service Unavailable HTTP status code cannot be returned
     * to the client via an HTTP redirect.)
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
     * state
     * REQUIRED if a "state" parameter was present in the client
     * authorization request.  The exact value received from the
     * client.
     *
     * For example, the authorization server redirects the user-agent by
     * sending the following HTTP response:
     *
     * HTTP/1.1 302 Found
     * Location: https://client.example.com/cb?error=access_denied&state=xyz
     */
    public function handleAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): array;

//    public function setNextAuthorizationRequestHandler(ResponseTypeInterface $responseType);

    public function getDefaultResponseMode(): string;

    public function getUnsupportedResponseModes(): array;

    public function isRegistrationOfRedirectUriRequired(): bool;
}
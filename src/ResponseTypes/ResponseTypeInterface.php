<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 19:12
 */

namespace OAuth2\ResponseTypes;


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
    function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData);

    function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array;

    function getDefaultResponseMode(): string;

    function getUnsupportedResponseModes(): array;
}
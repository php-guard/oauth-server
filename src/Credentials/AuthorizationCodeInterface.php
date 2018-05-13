<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:27
 */

namespace OAuth2\Credentials;


/**
 * Interface AuthorizationCodeInterface
 * @package OAuth2\Credentials
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3.1
 * The authorization code is obtained by using an authorization server
 * as an intermediary between the client and resource owner.  Instead of
 * requesting authorization directly from the resource owner, the client
 * directs the resource owner to an authorization server (via its
 * user-agent as defined in [RFC2616]), which in turn directs the
 * resource owner back to the client with the authorization code.
 *
 * Before directing the resource owner back to the client with the
 * authorization code, the authorization server authenticates the
 * resource owner and obtains authorization.  Because the resource owner
 * only authenticates with the authorization server, the resource
 * owner's credentials are never shared with the client.
 *
 * The authorization code provides a few important security benefits,
 * such as the ability to authenticate the client, as well as the
 * transmission of the access token directly to the client without
 * passing it through the resource owner's user-agent and potentially
 * exposing it to others, including the resource owner.
 */
interface AuthorizationCodeInterface
{
    function getCode(): string;

    function getScopes(): array;

    function getClientIdentifier(): string;

    function getResourceOwnerIdentifier(): string;

    function getExpiresAt(): \DateTimeInterface;

    function getRequestedScopes(): ?array;

    function getRedirectUri(): ?string;
}
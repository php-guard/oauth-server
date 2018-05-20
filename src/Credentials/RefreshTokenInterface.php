<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:24
 */

namespace OAuth2\Credentials;


/**
 * Interface RefreshTokenInterface
 * @package OAuth2\Credentials
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.5
 * Refresh tokens are credentials used to obtain access tokens.  Refresh
 * tokens are issued to the client by the authorization server and are
 * used to obtain a new access token when the current access token
 * becomes invalid or expires, or to obtain additional access tokens
 * with identical or narrower scope (access tokens may have a shorter
 * lifetime and fewer permissions than authorized by the resource
 * owner).  Issuing a refresh token is optional at the discretion of the
 * authorization server.  If the authorization server issues a refresh
 * token, it is included when issuing an access token (i.e., step (D) in
 * Figure 1).
 *
 * A refresh token is a string representing the authorization granted to
 * the client by the resource owner.  The string is usually opaque to
 * the client.  The token denotes an identifier used to retrieve the
 * authorization information.  Unlike access tokens, refresh tokens are
 * intended for use only with authorization servers and are never sent
 * to resource servers.
 */
interface RefreshTokenInterface extends TokenInterface
{
}
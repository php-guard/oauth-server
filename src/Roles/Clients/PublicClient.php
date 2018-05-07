<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:37
 */

namespace OAuth2\Roles\Clients;


/**
 * Class PublicClientType
 * @package OAuth2\Roles\Clients\Types
 *
 * @see     https://tools.ietf.org/html/rfc6749#section-2.1
 *
 * Client Types
 *
 *     Clients incapable of maintaining the confidentiality of their
 * credentials (e.g., clients executing on the device used by the
 * resource owner, such as an installed native application or a web
 * browser-based application), and incapable of secure client
 * authentication via any other means.
 */
abstract class PublicClient extends RegisteredClient
{
    public function hasCredentials(): bool
    {
        return false;
    }

    public function requireRedirectUri(): bool
    {
        return true;
    }
}
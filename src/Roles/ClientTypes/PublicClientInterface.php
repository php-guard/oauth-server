<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/05/2018
 * Time: 22:02
 */

namespace OAuth2\Roles\ClientTypes;

/**
 * Class PublicClientInterface
 * @package OAuth2\Roles\ClientTypes
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.1
 * Clients incapable of maintaining the confidentiality of their
 * credentials (e.g., clients executing on the device used by the
 * resource owner, such as an installed native application or a web
 * browser-based application), and incapable of secure client
 * authentication via any other means.
 */
interface PublicClientInterface
{

}
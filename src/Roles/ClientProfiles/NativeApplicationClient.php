<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:38
 */

namespace OAuth2\Roles\ClientProfiles;

use OAuth2\Roles\ClientTypes\PublicClient;


/**
 * Class NativeApplicationClient
 * @package OAuth2\Roles\Clients
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.1
 * A native application is a public client installed and executed on
 * the device used by the resource owner.  Protocol data and
 * credentials are accessible to the resource owner.  It is assumed
 * that any client authentication credentials included in the
 * application can be extracted.  On the other hand, dynamically
 * issued credentials such as access tokens or refresh tokens can
 * receive an acceptable level of protection.  At a minimum, these
 * credentials are protected from hostile servers with which the
 * application may interact.  On some platforms, these credentials
 * might be protected from other applications residing on the same
 * device.
 */
class NativeApplicationClient extends PublicClient
{
}
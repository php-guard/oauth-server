<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:39
 */

namespace OAuth2\Roles\ClientProfiles;

use OAuth2\Roles\ClientTypes\ConfidentialClient;


/**
 * Class WebApplicationClient
 * @package OAuth2\Roles\Clients
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.1
 * A web application is a confidential client running on a web
 * server.  Resource owners access the client via an HTML user
 * interface rendered in a user-agent on the device used by the
 * resource owner.  The client credentials as well as any access
 * token issued to the client are stored on the web server and are
 * not exposed to or accessible by the resource owner.
 */
class WebApplicationClient extends ConfidentialClient
{
}
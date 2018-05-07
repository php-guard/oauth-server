<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:39
 */

namespace OAuth2\Roles\Clients;


/**
 * Class UserAgentBasedApplicationClient
 * @package OAuth2\Roles\Clients
 *
 * @see     https://tools.ietf.org/html/rfc6749#section-2.1
 *
 * Client Types
 *
 *     A user-agent-based application is a public client in which the
 * client code is downloaded from a web server and executes within a
 * user-agent (e.g., web browser) on the device used by the resource
 * owner.  Protocol data and credentials are easily accessible (and
 * often visible) to the resource owner.  Since such applications
 * reside within the user-agent, they can make seamless use of the
 * user-agent capabilities when requesting authorization.
 */
class UserAgentBasedApplicationClient extends PublicClient
{

}
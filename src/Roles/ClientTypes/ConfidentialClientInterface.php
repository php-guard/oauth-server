<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 14/01/2018
 * Time: 15:38
 */

namespace OAuth2\Roles\ClientTypes;


use OAuth2\Roles\ClientInterface;

/**
 * Interface ConfidentialClientInterface
 * @package OAuth2\Roles\Clients
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.1
 * Clients capable of maintaining the confidentiality of their
 * credentials (e.g., client implemented on a secure server with
 * restricted access to the client credentials), or capable of secure
 * client authentication using other means.
 */
interface ConfidentialClientInterface extends ClientInterface
{
public function getPassword(): string;
}
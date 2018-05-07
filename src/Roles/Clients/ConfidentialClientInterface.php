<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 14/01/2018
 * Time: 15:38
 */

namespace OAuth2\Roles\Clients;


use OAuth2\Roles\ClientInterface;

/**
 * Interface ConfidentialClientInterface
 * @package OAuth2\Roles\Clients
 */
interface ConfidentialClientInterface extends ClientInterface
{
    function getPassword(): string;
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:37
 */

namespace OAuth2\Roles\ClientTypes;


/**
 * Class PublicClientType
 * @package OAuth2\Roles\Clients\Types
 */
abstract class PublicClient extends RegisteredClient implements PublicClientInterface
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
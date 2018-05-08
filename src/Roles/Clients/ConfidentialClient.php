<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:37
 */

namespace OAuth2\Roles\Clients;

/**
 * Class ClientPasswordType
 * @package OAuth2\Roles\Clients\Types
 *
 * @see     https://tools.ietf.org/html/rfc6749#section-2.1
 *
 * Client Types
 *
 *     Clients capable of maintaining the confidentiality of their
 * credentials (e.g., client implemented on a secure server with
 * restricted access to the client credentials), or capable of secure
 * client authentication using other means.
 */
abstract class ConfidentialClient extends RegisteredClient implements ConfidentialClientInterface
{
    protected $password;

    public function __construct(string $identifier, string $password, ClientMetadataInterface $metadata)
    {
        parent::__construct($identifier, $metadata);
        $this->password = $password;
    }

    /**
     * @return string
     */
    public function getPassword(): string
    {
        return $this->password;
    }

    public function hasCredentials(): bool
    {
        return true;
    }
}
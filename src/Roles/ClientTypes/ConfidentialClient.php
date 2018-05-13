<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:37
 */

namespace OAuth2\Roles\ClientTypes;

/**
 * Class ClientPasswordType
 * @package OAuth2\Roles\Clients\Types
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
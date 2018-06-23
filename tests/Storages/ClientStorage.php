<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 19:49
 */

namespace OAuth2\Tests\Storages;


use OAuth2\Roles\ClientProfiles\WebApplicationClient;
use OAuth2\Roles\ClientTypes\ClientMetadata;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Storages\ClientStorageInterface;

class ClientStorage implements ClientStorageInterface
{
    protected $clients;

    public function __construct()
    {
        $clientMetadata = new ClientMetadata();
        $clientMetadata->setRedirectUris(['http://client.com/callback']);
        $clientMetadata->setResponseTypes(['code', 'token']);
        $clientMetadata->setGrantTypes(['authorization_code', 'refresh_token', 'password', 'client_credentials']);
        $clientMetadata->setTokenEndpointAuthMethod('client_secret_post');
        $client = new WebApplicationClient('phpunit', 'password', $clientMetadata);
        $client->setHttpBasicAuthenticationSchemeSupported(true);
        $client->setTlsSupported(false);

        $this->clients[$client->getIdentifier()] = $client;
    }

    /**
     * @param string $identifier
     * @return null|RegisteredClient
     */
public function get(string $identifier): ?RegisteredClient
    {
        return $this->clients[$identifier] ?? null;
    }

public function getIdentifierSize(): ?int
    {
        return null;
    }
}
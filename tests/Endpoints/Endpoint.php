<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 13:45
 */

namespace OAuth2\Tests\Endpoints;


use OAuth2\Extensions\OpenID\Config;
use OAuth2\Extensions\OpenID\Storages\StorageManager;
use OAuth2\Roles\ClientProfiles\WebApplicationClient;
use OAuth2\Extensions\OpenID\Server;
use OAuth2\ScopePolicy\Policies\DefaultScopePolicy;
use OAuth2\Tests\Roles\ResourceOwner;
use OAuth2\Tests\Storages\AccessTokenStorage;
use OAuth2\Tests\Storages\AuthorizationCodeStorage;
use OAuth2\Tests\Storages\ClientStorage;
use OAuth2\Tests\Storages\RefreshTokenStorage;
use OAuth2\Tests\Storages\ResourceOwnerStorage;
use PHPUnit\Framework\TestCase;

abstract class Endpoint extends TestCase
{
    protected $config;
    /**
     * @var Server
     */
    protected $server;
    protected $storageManager;
    protected $resourceOwner;
    /**
     * @var WebApplicationClient
     */
    protected $client;

    public function setUp()
    {
        $clientStorage = new ClientStorage();
        $resourceOwnerStorage = new ResourceOwnerStorage();
        $scopePolicy = new DefaultScopePolicy(['email']);
        $this->config = new Config($scopePolicy, 'phpunit@oauth-server.com');
        $this->storageManager = new StorageManager(
            $clientStorage,
            $resourceOwnerStorage,
            new AuthorizationCodeStorage(),
            new AccessTokenStorage(),
            new RefreshTokenStorage());
        $this->resourceOwner = new ResourceOwner();
        $this->server = new Server($this->config, $this->storageManager, $this->resourceOwner);
        $this->client = $clientStorage->get('phpunit');
    }
}
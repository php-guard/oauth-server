<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 13:45
 */

namespace OAuth2\Tests\Endpoints;


use OAuth2\Extensions\PKCE\PKCEExtension;
use OAuth2\OAuthServer;
use OAuth2\OAuthServerBuilder;
use OAuth2\Roles\ClientProfiles\WebApplicationClient;
use OAuth2\ScopePolicy\Policies\DefaultScopePolicy;
use OAuth2\Tests\Roles\AuthorizationServerEndUser;
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
     * @var OAuthServer
     */
    protected $server;
    protected $storageManager;
    protected $authorizationServer;
    /**
     * @var WebApplicationClient
     */
    protected $client;

    public function setUp()
    {
        $clientStorage = new ClientStorage();

        $builder = new OAuthServerBuilder(new AuthorizationServerEndUser());
        $builder->getConfig()->setScopePolicy(new DefaultScopePolicy(['email']));
        $builder->getStorages()
            ->setResourceOwnerStorage(new ResourceOwnerStorage())
            ->setClientStorage($clientStorage)
            ->setAuthorizationCodeStorage(new AuthorizationCodeStorage())
            ->setAccessTokenStorage(new AccessTokenStorage())
            ->setRefreshTokenStorage(new RefreshTokenStorage());

        $builder->addExtension(new PKCEExtension());

        $this->server = $builder->build();

//        $scopePolicy = ;
//        $this->config = new Config($scopePolicy); //'phpunit@oauth-server.com'
//        $authorizationServerEndUser = new AuthorizationServerEndUser();

        $this->client = $clientStorage->get('phpunit');
    }
}
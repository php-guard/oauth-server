<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 21/04/2018
 * Time: 18:45
 */

namespace OAuth2;


use OAuth2\Roles\AuthorizationServer\AuthorizationServer;
use OAuth2\Roles\AuthorizationServer\EndUserInterface;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\FormEncodedBodyParameter;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\URIQueryParameter;
use OAuth2\Roles\ResourceServer\ResourceServer;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;

class OAuthServer
{
    private $authorizationServer;
    private $resourceServer;
    private $scopePolicyManager;
    private $storageManager;
    /**
     * @var Config
     */
    private $config;
    /**
     * @var EndUserInterface
     */
    private $endUser;

    public function __construct(Config $config,
                                EndUserInterface $endUser,
                                StorageManager $storageManager)
    {
        $this->config = $config;
        $this->endUser = $endUser;

        $this->storageManager = $storageManager;

        $this->scopePolicyManager = new ScopePolicyManager($config);

        $this->authorizationServer = $this->createAuthorizationServer();
        $this->resourceServer = $this->createResourceServer();
    }

    protected function createAuthorizationServer() {
        return new AuthorizationServer($this->config, $this->storageManager, $this->scopePolicyManager, $this->endUser);
    }

    protected function createResourceServer() {
        return (new ResourceServer($this->storageManager, $this->scopePolicyManager))
            ->addBearerAuthenticationMethod(new FormEncodedBodyParameter())
            ->addBearerAuthenticationMethod(new URIQueryParameter());
    }

    /**
     * @return AuthorizationServer
     */
    public function getAuthorizationServer(): AuthorizationServer
    {
        return $this->authorizationServer;
    }

    /**
     * @return ResourceServer
     */
    public function getResourceServer(): ResourceServer
    {
        return $this->resourceServer;
    }


}
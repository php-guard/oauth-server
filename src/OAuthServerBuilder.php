<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 23/06/2018
 * Time: 18:08
 */

namespace OAuth2;


use OAuth2\Extensions\ExtensionInterface;
use OAuth2\Roles\AuthorizationServer\AuthorizationServerBuilder;
use OAuth2\Roles\AuthorizationServer\EndUserInterface;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\FormEncodedBodyParameter;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\URIQueryParameter;
use OAuth2\Roles\ResourceServer\ResourceServer;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;
use OAuth2\Storages\StorageRepositoryBuilder;

class OAuthServerBuilder
{
    /**
     * @var ExtensionInterface[]
     */
    protected $extensions = [];

    /**
     * @var Config
     */
    protected $config;

    /**
     * @var StorageRepositoryBuilder
     */
    protected $storages;
    /**
     * @var EndUserInterface
     */
    private $endUser;

    public function __construct(EndUserInterface $endUser)
    {
        $this->config = new Config();
        $this->storages = new StorageRepositoryBuilder();
        $this->endUser = $endUser;
    }

    public function getConfig() {
        return $this->config;
    }

    public function getStorages() {
        return $this->storages;
    }

    public function addExtension(ExtensionInterface $extension)
    {
        $this->extensions[] = $extension;
    }

    public function build()
    {
        $scopePolicyManager= new ScopePolicyManager($this->config->getScopePolicy());
        $storageManager = $this->storages->build();

        $authorizationServerBuilder = new AuthorizationServerBuilder($this->config, $storageManager, $scopePolicyManager, $this->endUser);
        foreach ($this->extensions as $extension) {
            $extension->extendAuthorizationServerBuilder($authorizationServerBuilder);
        }
        $authorizationServer = $authorizationServerBuilder->build();

        $resourceServer = (new ResourceServer($storageManager, $scopePolicyManager))
            ->addBearerAuthenticationMethod(new FormEncodedBodyParameter())
            ->addBearerAuthenticationMethod(new URIQueryParameter());

        $server = new OAuthServer($authorizationServer, $resourceServer);

        return $server;
    }
}
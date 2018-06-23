<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 22:25
 */

namespace OAuth2\Roles\AuthorizationServer;


use OAuth2\Config;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;

class AuthorizationServerBuilder
{
    /**
     * @var Config
     */
    private $config;
    /**
     * @var StorageManager
     */
    private $storageManager;
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;
    /**
     * @var EndUserInterface
     */
    private $authorizationServerEndUser;

    public function __construct(Config $config,
                                StorageManager $storageManager,
                                ScopePolicyManager $scopePolicyManager,
                                EndUserInterface $authorizationServerEndUser)
    {
        $this->config = $config;
        $this->storageManager = $storageManager;
        $this->scopePolicyManager = $scopePolicyManager;
        $this->authorizationServerEndUser = $authorizationServerEndUser;
    }

    public function addExtension($extension)
    {

    }

    public function build()
    {
        $this->storageManager
        $this->grantTypeManager,
            $this->clientAuthenticationMethodManager


        $authorizationRequestBuilder = null;
        $authorizationServerEndUser = null;

        return new AuthorizationServer($authorizationRequestBuilder, $authorizationServerEndUser);
    }
}
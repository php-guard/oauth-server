<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 12/03/2018
 * Time: 21:26
 */

namespace OAuth2\Extensions\OpenID\Roles;


use OAuth2\Endpoints\AuthorizationRequestBuilder;
use OAuth2\Extensions\OpenID\Config;
use OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint;
use OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow;
use OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows\HybridFlow;
use OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows\ImplicitFlow;
use OAuth2\Extensions\OpenID\IdTokenManager;
use OAuth2\Extensions\OpenID\Storages\StorageManager;
use OAuth2\Roles\AuthorizationServerEndUserInterface;

class AuthorizationServer extends \OAuth2\Roles\AuthorizationServer
{
    protected $idTokenManager;

    public function __construct(Config $config, StorageManager $storageManager,
                                AuthorizationServerEndUserInterface $authorizationServerEndUser)
    {
        parent::__construct($config, $storageManager, $authorizationServerEndUser);

        $this->idTokenManager = new IdTokenManager($config);

        $this->flowManager->addFlow(new AuthorizationCodeFlow(
            $storageManager->getAuthorizationCodeStorage(),
            $storageManager->getAccessTokenStorage(),
            $storageManager->getRefreshTokenStorage(),
            $storageManager->getClientStorage(),
            $storageManager->getResourceOwnerStorage(),
            $this->idTokenManager
        ));

        $this->flowManager->addFlow(new ImplicitFlow(
            $storageManager->getAccessTokenStorage(),
            $storageManager->getRefreshTokenStorage(),
            $this->idTokenManager
        ));

        $this->flowManager->addFlow(new HybridFlow(
            $storageManager->getAuthorizationCodeStorage(),
            $storageManager->getAccessTokenStorage(),
            $storageManager->getRefreshTokenStorage(),
            $this->idTokenManager
        ));

        $authorizationRequestBuilder = new AuthorizationRequestBuilder(
            $storageManager->getClientStorage(),
            $this->responseTypeManager,
            $this->responseModeManager,
            $this->scopePolicyManager
        );
        $this->authorizationEndpoint = new AuthorizationEndpoint(
            $authorizationRequestBuilder,
            $authorizationServerEndUser
        );
    }
}
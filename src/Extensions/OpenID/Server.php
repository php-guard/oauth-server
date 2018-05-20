<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 12/03/2018
 * Time: 21:26
 */

namespace OAuth2\Extensions\OpenID;


use OAuth2\Extensions\OpenID\Endpoints\AuthorizationEndpoint;
use OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow;
use OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows\HybridFlow;
use OAuth2\Extensions\OpenID\AuthorizationGrantTypes\Flows\ImplicitFlow;
use OAuth2\Extensions\OpenID\Roles\ResourceOwnerInterface;
use OAuth2\Extensions\OpenID\Storages\StorageManager;

class Server extends \OAuth2\Server
{
    protected $idTokenManager;

    public function __construct(Config $config, StorageManager $storageManager, ResourceOwnerInterface $resourceOwner)
    {
        parent::__construct($config, $storageManager, $resourceOwner);

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

        $this->authorizationEndpoint = new AuthorizationEndpoint(
            $this->responseTypeManager,
            $this->responseModeManager,
            $this->scopePolicyManager,
            $resourceOwner,
            $storageManager->getClientStorage(),
            $this->idTokenManager
        );
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/03/2018
 * Time: 16:21
 */

namespace OAuth2\Extensions\OpenID\Storages;


use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Storages\ClientStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;

class StorageManager extends \OAuth2\Storages\StorageManager
{
    public function __construct(ClientStorageInterface $clientStorage,
                                ResourceOwnerStorageInterface $resourceOwnerStorage,
                                AuthorizationCodeStorageInterface $authorizationCodeStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($clientStorage,
            $resourceOwnerStorage,
            $authorizationCodeStorage,
            $accessTokenStorage,
            $refreshTokenStorage);
    }

    /**
     * @return \OAuth2\Extensions\OpenID\Storages\AuthorizationCodeStorageInterface
     */
    public function getAuthorizationCodeStorage(): AuthorizationCodeStorageInterface
    {
        return parent::getAuthorizationCodeStorage();
    }

}
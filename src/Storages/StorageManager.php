<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 18:20
 */

namespace OAuth2\Storages;


class StorageManager
{
    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;
    /**
     * @var ResourceOwnerStorageInterface
     */
    private $resourceOwnerStorage;
    /**
     * @var AuthorizationCodeStorageInterface
     */
    private $authorizationCodeStorage;
    /**
     * @var AccessTokenStorageInterface
     */
    private $accessTokenStorage;
    /**
     * @var RefreshTokenStorageInterface
     */
    private $refreshTokenStorage;

    public function __construct(
        ClientStorageInterface $clientStorage,
        ResourceOwnerStorageInterface $resourceOwnerStorage,
        AuthorizationCodeStorageInterface $authorizationCodeStorage,
        AccessTokenStorageInterface $accessTokenStorage,
        RefreshTokenStorageInterface $refreshTokenStorage)
    {
        $this->clientStorage = $clientStorage;
        $this->resourceOwnerStorage = $resourceOwnerStorage;
        $this->authorizationCodeStorage = $authorizationCodeStorage;
        $this->accessTokenStorage = $accessTokenStorage;
        $this->refreshTokenStorage = $refreshTokenStorage;
    }

    /**
     * @return ClientStorageInterface
     */
    public function getClientStorage(): ClientStorageInterface
    {
        return $this->clientStorage;
    }

    /**
     * @return ResourceOwnerStorageInterface
     */
    public function getResourceOwnerStorage(): ResourceOwnerStorageInterface
    {
        return $this->resourceOwnerStorage;
    }

    /**
     * @return AuthorizationCodeStorageInterface
     */
    public function getAuthorizationCodeStorage(): AuthorizationCodeStorageInterface
    {
        return $this->authorizationCodeStorage;
    }

    /**
     * @return AccessTokenStorageInterface
     */
    public function getAccessTokenStorage(): AccessTokenStorageInterface
    {
        return $this->accessTokenStorage;
    }

    /**
     * @return RefreshTokenStorageInterface
     */
    public function getRefreshTokenStorage(): RefreshTokenStorageInterface
    {
        return $this->refreshTokenStorage;
    }
}
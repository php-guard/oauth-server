<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 23/06/2018
 * Time: 18:36
 */

namespace OAuth2\Storages;


class StorageRepositoryBuilder
{
    /**
     * @var ClientStorageInterface|null
     */
    private $clientStorage;
    /**
     * @var ResourceOwnerStorageInterface|null
     */
    private $resourceOwnerStorage;
    /**
     * @var AuthorizationCodeStorageInterface|null
     */
    private $authorizationCodeStorage;
    /**
     * @var AccessTokenStorageInterface|null
     */
    private $accessTokenStorage;
    /**
     * @var RefreshTokenStorageInterface|null
     */
    private $refreshTokenStorage;

    /**
     * @return StorageManager
     */
    public function build(): StorageManager
    {
        if(!$this->clientStorage) {
            throw new \InvalidArgumentException('Client storage is missing');
        }
        if(!$this->resourceOwnerStorage) {
            throw new \InvalidArgumentException('Resource owner storage is missing');
        }
        if(!$this->authorizationCodeStorage) {
            throw new \InvalidArgumentException('Authorization code storage is missing');
        }
        if(!$this->accessTokenStorage) {
            throw new \InvalidArgumentException('Access token storage is missing');
        }
        if(!$this->refreshTokenStorage) {
            throw new \InvalidArgumentException('Refresh token storage is missing');
        }

        return new StorageManager(
            $this->clientStorage,
            $this->resourceOwnerStorage,
            $this->authorizationCodeStorage,
            $this->accessTokenStorage,
            $this->refreshTokenStorage
        );
    }

    /**
     * @param ClientStorageInterface $clientStorage
     * @return StorageRepositoryBuilder
     */
    public function setClientStorage(ClientStorageInterface $clientStorage): self
    {
        $this->clientStorage = $clientStorage;
        return $this;
    }

    /**
     * @param ResourceOwnerStorageInterface $resourceOwnerStorage
     * @return StorageRepositoryBuilder
     */
    public function setResourceOwnerStorage(ResourceOwnerStorageInterface $resourceOwnerStorage): self
    {
        $this->resourceOwnerStorage = $resourceOwnerStorage;
        return $this;
    }

    /**
     * @param AuthorizationCodeStorageInterface $authorizationCodeStorage
     * @return StorageRepositoryBuilder
     */
    public function setAuthorizationCodeStorage(AuthorizationCodeStorageInterface $authorizationCodeStorage): self
    {
        $this->authorizationCodeStorage = $authorizationCodeStorage;
        return $this;
    }

    /**
     * @param AccessTokenStorageInterface $accessTokenStorage
     * @return StorageRepositoryBuilder
     */
    public function setAccessTokenStorage(AccessTokenStorageInterface $accessTokenStorage): self
    {
        $this->accessTokenStorage = $accessTokenStorage;
        return $this;
    }

    /**
     * @param RefreshTokenStorageInterface $refreshTokenStorage
     * @return StorageRepositoryBuilder
     */
    public function setRefreshTokenStorage(RefreshTokenStorageInterface $refreshTokenStorage): self
    {
        $this->refreshTokenStorage = $refreshTokenStorage;
        return $this;
    }
}
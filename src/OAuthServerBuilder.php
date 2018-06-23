<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 23/06/2018
 * Time: 18:08
 */

namespace OAuth2;


use OAuth2\Extensions\ExtensionInterface;
use OAuth2\Roles\AuthorizationServer\EndUserInterface;
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
        foreach ($this->extensions as $extension) {
            $extension->load($this);
        }
        $storageManager = $this->storages->build();
        return new OAuthServer($this->config, $this->endUser, $storageManager);
    }
}
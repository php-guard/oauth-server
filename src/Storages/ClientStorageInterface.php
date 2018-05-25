<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 21:48
 */

namespace OAuth2\Storages;



use OAuth2\Roles\ClientTypes\RegisteredClient;

interface ClientStorageInterface
{
    /**
     * @param string $identifier
     * @return null|RegisteredClient
     */
public function get(string $identifier): ?RegisteredClient;

public function getIdentifierSize(): ?int;
}
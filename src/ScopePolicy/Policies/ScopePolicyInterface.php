<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 09:57
 */

namespace OAuth2\ScopePolicy\Policies;


use OAuth2\Roles\ClientInterface;

interface ScopePolicyInterface
{
    /**
     * @param ClientInterface $client
     * @param array|null $scopes
     * @return array|null
     */
public function getScopes(ClientInterface $client, ?array $scopes): array;
}
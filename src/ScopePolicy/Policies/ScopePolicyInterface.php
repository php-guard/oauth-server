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
     * @param string|null     $scope
     * @return array|null
     */
    function getScopes(ClientInterface $client, ?string $scope): array;
}
<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 11:50
 */

namespace OAuth2\ScopePolicy\Policies;


use OAuth2\Roles\ClientInterface;

class DefaultScopePolicy implements ScopePolicyInterface
{
    /**
     * @var array
     */
    private $scopes = [];

    public function setScopes(array $scopes)
    {
        $this->scopes = $scopes;
    }

    public function getScopes(ClientInterface $client, ?array $scopes): array
    {
        return empty($scopes) ? $this->scopes : $scopes;
    }
}
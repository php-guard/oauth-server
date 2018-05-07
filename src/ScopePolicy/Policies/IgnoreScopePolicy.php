<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 11:49
 */

namespace OAuth2\ScopePolicy\Policies;

use OAuth2\Roles\ClientInterface;

class IgnoreScopePolicy implements ScopePolicyInterface
{
    /**
     * @var array
     */
    private $scopes;

    public function __construct(array $scopes)
    {
        $this->scopes = $scopes;
    }

    public function getScopes(ClientInterface $client, ?string $scope): array
    {
        return $this->scopes;
    }
}
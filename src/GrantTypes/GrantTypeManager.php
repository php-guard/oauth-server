<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 09:53
 */

namespace OAuth2\GrantTypes;


class GrantTypeManager
{
    protected $grantTypes = [];

    public function addGrantType(string $identifier, GrantTypeInterface $grantType)
    {
        $this->grantTypes[$identifier] = $grantType;
    }

    public function getGrantType(string $identifier): ?GrantTypeInterface
    {
        return $this->grantTypes[$identifier] ?? null;
    }
}
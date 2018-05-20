<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 09:53
 */

namespace OAuth2\AuthorizationGrantTypes;


class GrantTypeManager
{
    protected $grantTypes = [];

    /**
     * @param string $identifier
     * @param GrantTypeInterface $grantType
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.5
     * The client uses an extension grant type by specifying the grant type
     * using an absolute URI (defined by the authorization server) as the
     * value of the "grant_type" parameter of the token endpoint, and by
     * adding any additional parameters necessary.
     */
    public function addGrantType(string $identifier, GrantTypeInterface $grantType)
    {
        $this->grantTypes[$identifier] = $grantType;
    }

    public function getGrantType(string $identifier): ?GrantTypeInterface
    {
        return $this->grantTypes[$identifier] ?? null;
    }
}
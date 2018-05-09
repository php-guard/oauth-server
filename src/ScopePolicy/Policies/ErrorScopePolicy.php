<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 10:20
 */

namespace OAuth2\ScopePolicy\Policies;


use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\ClientInterface;

class ErrorScopePolicy implements ScopePolicyInterface
{
    /**
     * @param ClientInterface $client
     * @param string|null     $scope
     * @return array|null
     * @throws OAuthException
     */
    public function getScopes(ClientInterface $client, ?array $scopes): array
    {
        if (empty($scopes)) {
            throw new OAuthException('invalid_scope',
                'The request is missing the required parameter scope.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }
        return $scopes;
    }
}
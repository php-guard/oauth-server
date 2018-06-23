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

/**
 * Class ErrorScopePolicy
 * @package OAuth2\ScopePolicy\Policies
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 * If the client omits the scope parameter when requesting
 * authorization, the authorization server MUST either process the
 * request using a pre-defined default value or fail the request
 * indicating an invalid scope.
 */
class ErrorScopePolicy implements ScopePolicyInterface
{
    /**
     * @param ClientInterface $client
     * @param array|null $scopes
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
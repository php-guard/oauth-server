<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 11:50
 */

namespace OAuth2\ScopePolicy\Policies;


use OAuth2\Roles\ClientInterface;

/**
 * Class DefaultScopePolicy
 * @package OAuth2\ScopePolicy\Policies
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.3 *
 * If the client omits the scope parameter when requesting
 * authorization, the authorization server MUST either process the
 * request using a pre-defined default value or fail the request
 * indicating an invalid scope.
 */
class DefaultScopePolicy implements ScopePolicyInterface
{
    /**
     * @var array
     */
    private $scopes = [];

    public function __construct(array $scopes)
    {
        if(empty($scopes)) {
            throw new \InvalidArgumentException('Scope must not be an empty array');
        }
        $this->scopes = $scopes;
    }

    public function getScopes(ClientInterface $client, ?array $scopes): array
    {
        return empty($scopes) ? $this->scopes : $scopes;
    }
}
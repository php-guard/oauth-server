<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 11:49
 */

namespace OAuth2\ScopePolicy\Policies;

use OAuth2\Roles\ClientInterface;

/**
 * Class IgnoreScopePolicy
 * @package OAuth2\ScopePolicy\Policies
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 * The authorization server MAY fully or partially ignore the scope
 * requested by the client, based on the authorization server policy or
 * the resource owner's instructions.
 */
class IgnoreScopePolicy implements ScopePolicyInterface
{
    /**
     * @var array
     */
    private $scopes;

    public function __construct(array $scopes)
    {
        if(empty($scopes)) {
            throw new \InvalidArgumentException('Scope must not be an empty array');
        }
        $this->scopes = $scopes;
    }

    public function getScopes(ClientInterface $client, ?array $scope): array
    {
        return $this->scopes;
    }
}
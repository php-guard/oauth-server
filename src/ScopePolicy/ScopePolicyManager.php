<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 09:54
 */

namespace OAuth2\ScopePolicy;


use OAuth2\Config;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\Clients\RegisteredClient;


class ScopePolicyManager
{
    /**
     * @var Config
     */
    private $config;

    /**
     * ScopePolicyManager constructor.
     * @param Config $config
     * @throws \Exception
     */
    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    /**
     * @param ClientInterface $client
     * @param string|null     $scope
     * @return array|null
     */
    public function getScopes(ClientInterface $client, ?string $scope): array
    {
        return $this->config->getScopePolicy()->getScopes($client, $scope);
    }

    /**
     * @param ClientInterface $client
     * @param array           $scopes
     * @throws OAuthException
     */
    public function verifyScopes(ClientInterface $client, array $scopes): void
    {
        if (empty($scopes)) {
            throw new OAuthException('invalid_scope',
                'The request scope is unknown.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if ($client instanceof RegisteredClient && !is_null($client->getMetadata()->getScope())) {
            $supportedScopes = explode(' ', $client->getMetadata()->getScope());
            if (!empty(array_diff($scopes, $supportedScopes))) {
                throw new OAuthException('invalid_scope',
                    'The request scope is invalid. Supported scopes : ' . $client->getMetadata()->getScope(),
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }
        }
    }
}
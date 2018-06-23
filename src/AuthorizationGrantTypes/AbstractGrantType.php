<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 17:56
 */

namespace OAuth2\AuthorizationGrantTypes;


use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

abstract class AbstractGrantType implements GrantTypeInterface
{
    /**
     * @var AccessTokenStorageInterface
     */
    protected $accessTokenStorage;
    /**
     * @var RefreshTokenStorageInterface
     */
    protected $refreshTokenStorage;

    public function __construct(AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        $this->accessTokenStorage = $accessTokenStorage;
        $this->refreshTokenStorage = $refreshTokenStorage;
    }

    protected function issueTokens(array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier = null,
                                   ?string $authorizationCode = null)
    {
        return array_merge(
            $this->issueAccessToken($scopes, $clientIdentifier, $resourceOwnerIdentifier, $authorizationCode),
            $this->issueRefreshToken($scopes, $clientIdentifier, $resourceOwnerIdentifier, $authorizationCode)
        );
    }

    protected function issueAccessToken(array $scopes, string $clientIdentifier,
                                        ?string $resourceOwnerIdentifier = null, ?string $authorizationCode = null): array
    {
        $accessToken = $this->accessTokenStorage->generate($scopes, $clientIdentifier,
            $resourceOwnerIdentifier, $authorizationCode);

        return [
            'access_token' => $accessToken->getToken(),
            'token_type' => $accessToken->getType(),
            'expires_in' => $this->accessTokenStorage->getLifetime()
        ];
    }

    protected function issueRefreshToken(array $scopes, string $clientIdentifier,
                                         ?string $resourceOwnerIdentifier = null, ?string $authorizationCode = null)
    {
        $accessToken = $this->refreshTokenStorage->generate($scopes, $clientIdentifier, $resourceOwnerIdentifier, $authorizationCode);
        return [
            'refresh_token' => $accessToken->getToken()
        ];
    }
}
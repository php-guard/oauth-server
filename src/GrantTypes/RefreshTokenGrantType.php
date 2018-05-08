<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 14:36
 */

namespace OAuth2\GrantTypes;


use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;

class RefreshTokenGrantType extends AbstractGrantType implements GrantTypeInterface
{
    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (empty($requestData['refresh_token'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter refresh_token.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $refreshToken = $this->refreshTokenStorage->get($requestData['refresh_token']);

        if (!$refreshToken || $refreshToken->getClientIdentifier() !== $tokenEndpoint->getClient()->getIdentifier()) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter refresh_token.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        // TODO Config alwaysRevokeRefreshTokenOnUse
        $this->refreshTokenStorage->revoke($refreshToken->getToken());

        if ($this->refreshTokenStorage->hasExpired($refreshToken)) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter refresh_token. The token has expired.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $requestedScopes = explode(' ', $requestData['scope']);
        $scopes = $refreshToken->getScopes();

        if (!empty($requestData['scope'])) {
            if (!empty(array_diff($requestedScopes, $refreshToken->getScopes()))) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter scope.',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
            $scopes = $requestedScopes;
        }

        // TODO Config issueTokens or only accessToken
        return $this->issueTokens($scopes, $refreshToken->getClientIdentifier(), $refreshToken->getResourceOwnerIdentifier());
    }
}
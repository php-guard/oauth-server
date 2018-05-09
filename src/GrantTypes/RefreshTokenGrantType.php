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
use Symfony\Component\VarDumper\VarDumper;

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
//        $this->refreshTokenStorage->revoke($refreshToken->getToken());

        if ($this->refreshTokenStorage->hasExpired($refreshToken)) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter refresh_token. The token has expired.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $scopes = $refreshToken->getScopes();
        $requestedScopes = empty(trim($requestData['scope'])) ? null : array_filter(explode(' ', $requestData['scope']));

        if (!empty($requestedScopes)) {
            if (!empty(array_diff($requestedScopes, $refreshToken->getScopes()))) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter scope.',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
            $scopes = $requestedScopes;
        }

        // TODO Config issueTokens or only accessToken

        $responseData = $this->issueTokens($scopes, $refreshToken->getClientIdentifier(), $refreshToken->getResourceOwnerIdentifier());

        if(is_null($requestedScopes) ||
            array_diff($requestedScopes, $scopes)) {
            $responseData['scope'] = implode(' ', $scopes);
        }

        return $responseData;
    }
}
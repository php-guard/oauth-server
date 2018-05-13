<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 14:36
 */

namespace OAuth2\AuthorizationGrantTypes;


use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Helper;
use OAuth2\ScopePolicy\ScopePolicyManager;

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
        $requestedScopes = ScopePolicyManager::scopeStringToArray($requestData['scope'] ?? null);

        if (!empty($requestedScopes)) {
            if (!empty(array_diff($requestedScopes, $refreshToken->getScopes()))) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter scope.',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
            $scopes = $requestedScopes;
        }

        // TODO Config issueTokens or only accessToken

        $responseData = $this->issueTokens(
            $scopes,
            $refreshToken->getClientIdentifier(),
            $refreshToken->getResourceOwnerIdentifier()
        );

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.3
         * The authorization and token endpoints allow the client to specify the
         * scope of the access request using the "scope" request parameter.  In
         * turn, the authorization server uses the "scope" response parameter to
         * inform the client of the scope of the access token issued.
         */
        if (Helper::array_equals($requestedScopes, $scopes)) {
            $responseData['scope'] = implode(' ', $scopes);
        }

        return $responseData;
    }
}
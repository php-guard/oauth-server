<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 23:43
 */

namespace OAuth2\Extensions\PKCE\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\PKCE\Credentials\CodeChallenge;
use OAuth2\Extensions\PKCE\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Helper;
use OAuth2\Roles\ClientTypes\PublicClient;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

/**
 * Class AuthorizationCodeFlow
 * @package OAuth2\Extensions\PKCE\Flows
 * rfc https://tools.ietf.org/html/rfc7636
 */
class AuthorizationCodeFlow extends \OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow
{
    /**
     * @var AuthorizationCodeStorageInterface
     */
    protected $authorizationCodeStorage;

    /**
     * AuthorizationCodeFlow constructor.
     * @param \OAuth2\GrantFlows\AuthorizationCodeFlow $authorizationCodeFlow
     * @param AuthorizationCodeStorageInterface   $authorizationCodeStorage
     * @param AccessTokenStorageInterface         $accessTokenStorage
     * @param RefreshTokenStorageInterface        $refreshTokenStorage
     */
    public function __construct(\OAuth2\GrantFlows\AuthorizationCodeFlow $authorizationCodeFlow,
                                AuthorizationCodeStorageInterface $authorizationCodeStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($authorizationCodeStorage, $accessTokenStorage, $refreshTokenStorage);
        $this->authorizationCodeStorage = $authorizationCodeStorage;
    }

    /**
     * @param AuthorizationEndpoint $authorizationEndpoint
     * @param array                 $requestData
     * @return array
     * @throws OAuthException
     */
    function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        $authorizationCode = $this->createAuthorizationCode($authorizationEndpoint);

        if (empty($requestData['code_challenge'])) {
            if ($authorizationEndpoint->getClient() instanceof PublicClient) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter code_challenge for public clients.',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
        } else {
            $codeChallengeMethod = empty($requestData['code_challenge_method']) ? 'plain' : $requestData['code_challenge_method'];
            if (!in_array($codeChallengeMethod, ['plain', 'S256'])) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter code_challenge_method. Supported : plain, S256.',
                    'https://tools.ietf.org/html/rfc7636#section-4');
            }

            $codeChallenge = new CodeChallenge($requestData['code_challenge'], $codeChallengeMethod);
            $this->authorizationCodeStorage->associate($codeChallenge, $authorizationCode);
        }

        return $this->saveAndGetResult($authorizationCode);
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (empty($requestData['code'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter code.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }
        $code = $requestData['code'];

        $authorizationCode = $this->authorizationCodeStorage->get($code);

        /**
         * ensure that the authorization code was issued to the authenticated
         * confidential client, or if the client is public, ensure that the
         * code was issued to "client_id" in the request,
         */
        if (!$authorizationCode || $authorizationCode->getClientIdentifier() !== $tokenEndpoint->getClient()->getIdentifier()) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter code.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $this->authorizationCodeStorage->revoke($code);

        /**
         * verify that the authorization code is valid
         */
        if ($this->authorizationCodeStorage->hasExpired($authorizationCode)) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter code. The code has expired.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        /**
         * ensure that the "redirect_uri" parameter is present if the
         * "redirect_uri" parameter was included in the initial authorization
         * request as described in Section 4.1.1, and if included ensure that
         * their values are identical.
         */
        if ($authorizationCode->getRedirectUri()) {
            if (empty($requestData['redirect_uri'])) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter redirect_uri',
                    'https://tools.ietf.org/html/rfc7636#section-4.1');
            }
            if ($requestData['redirect_uri'] !== $authorizationCode->getRedirectUri()) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter redirect_uri',
                    'https://tools.ietf.org/html/rfc7636#section-4.1');
            }
        }

        $codeChallenge = $this->authorizationCodeStorage->getCodeChallenge($authorizationCode);

        if ($codeChallenge && $codeChallenge->getCodeChallenge()) {
            if (empty($requestData['code_verifier'])) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter code_verifier',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }

            if ($codeChallenge->getCodeChallengeMethod() === 'S256') {
                /**
                 * If the "code_challenge_method" from Section 4.3 was "S256", the
                 * received "code_verifier" is hashed by SHA-256, base64url-encoded, and
                 * then compared to the "code_challenge", i.e.:
                 */
                $hashedCodeVerifier = Helper::base64url_encode(hash('sha256', $requestData['code_verifier']));
            } else {
                /**
                 * If the "code_challenge_method" from Section 4.3 was "plain", they are
                 * compared directly, i.e.:
                 */
                $hashedCodeVerifier = $requestData['code_verifier'];
            }

            /**
             * If the values are equal, the token endpoint MUST continue processing
             * as normal (as defined by OAuth 2.0 [RFC6749]).  If the values are not
             * equal, an error response indicating "invalid_grant" as described in
             * Section 5.2 of [RFC6749] MUST be returned.
             */
            if ($hashedCodeVerifier !== $codeChallenge->getCodeChallenge()) {
                throw new OAuthException('invalid_grant',
                    'The request includes the invalid parameter code_verifier',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
        }

        return $this->issueTokens($authorizationCode->getScopes(),
            $authorizationCode->getResourceOwnerIdentifier(), $authorizationCode->getCode());
    }

}
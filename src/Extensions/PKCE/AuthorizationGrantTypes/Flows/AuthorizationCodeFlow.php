<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 23:43
 */

namespace OAuth2\Extensions\PKCE\AuthorizationGrantTypes\Flows;


use OAuth2\AuthorizationGrantTypes\Flows\FlowInterface;
use OAuth2\Config;
use OAuth2\Endpoints\Authorization\AuthorizationRequest;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\PKCE\Credentials\AuthorizationCodeInterface;
use OAuth2\Extensions\PKCE\Endpoints\Authorization\AuthorizationRequest as PKCEAuthorizationRequest;
use OAuth2\Extensions\PKCE\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Helper;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;

/**
 * Class AuthorizationCodeFlow
 * @package OAuth2\Extensions\PKCE\Flows
 * rfc https://tools.ietf.org/html/rfc7636
 */
class AuthorizationCodeFlow implements FlowInterface
{
    /**
     * @var AuthorizationCodeStorageInterface
     */
    protected $authorizationCodeStorage;
    /**
     * @var \OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow
     */
    private $authorizationCodeFlow;

    /**
     * AuthorizationCodeFlow constructor.
     * @param \OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow $authorizationCodeFlow
     */
    public function __construct(\OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow $authorizationCodeFlow)
    {
        $this->authorizationCodeFlow = $authorizationCodeFlow;
    }

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @return array
     */
    public function handleAuthorizationRequest(AuthorizationRequest $authorizationRequest): array
    {
        $response = $this->authorizationCodeFlow->handleAuthorizationRequest($authorizationRequest);

        if ($authorizationRequest instanceof PKCEAuthorizationRequest && $authorizationRequest->getCodeChallenge()) {
            $this->authorizationCodeStorage->setCodeChallenge($this->authorizationCodeFlow->getAuthorizationCode(),
                $authorizationRequest->getCodeChallenge(),
                $authorizationRequest->getCodeChallengeMethod());
        }

        return $response;
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        $response = $this->authorizationCodeFlow->handleAccessTokenRequest($tokenEndpoint, $requestData);
        $authorizationCode = $this->authorizationCodeFlow->getAuthorizationCode();

        if (!$authorizationCode instanceof AuthorizationCodeInterface) {
            return $response;
        }

        if ($authorizationCode->getCodeChallenge()) {
            if (empty($requestData['code_verifier'])) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter code_verifier',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }

            if ($authorizationCode->getCodeChallengeMethod() === 'S256') {
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
            if ($hashedCodeVerifier !== $authorizationCode->getCodeChallenge()) {
                throw new OAuthException('invalid_grant',
                    'The request includes the invalid parameter code_verifier',
                    'https://tools.ietf.org/html/rfc7636#section-4.4');
            }
        }

        return $response;
    }

    /**
     * @return string[]
     */
    public function getResponseTypes(): array
    {
        return $this->authorizationCodeFlow->getResponseTypes();
    }

    /**
     * @return string[]
     */
    public function getGrantTypes(): array
    {
        return $this->authorizationCodeFlow->getGrantTypes();
    }

    public function getDefaultResponseMode(): string
    {
        return $this->authorizationCodeFlow->getDefaultResponseMode();
    }

    public function getUnsupportedResponseModes(): array
    {
        return $this->authorizationCodeFlow->getUnsupportedResponseModes();
    }

    public function isRegistrationOfRedirectUriRequired(): bool
    {
        return $this->authorizationCodeFlow->isRegistrationOfRedirectUriRequired();
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\Flows;


use OAuth2\Credentials\AuthorizationCode;
use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\GrantTypes\AbstractGrantType;
use OAuth2\Roles\Clients\RegisteredClient;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\AuthorizationCodeStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use Symfony\Component\VarDumper\VarDumper;

class AuthorizationCodeFlow extends AbstractGrantType implements FlowInterface
{
    protected $authorizationCodeStorage;
    /**
     * @var AuthorizationCode
     */
    protected $authorizationCode;

    public function __construct(AuthorizationCodeStorageInterface $authorizationCodeStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->authorizationCodeStorage = $authorizationCodeStorage;
    }

    public function getResponseTypes(): array
    {
        return ['code'];
    }

    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
    }

    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        $this->authorizationCode = $this->authorizationCodeStorage->generate(
            $authorizationEndpoint->getScopes(),
            $authorizationEndpoint->getClient()->getIdentifier(),
            $authorizationEndpoint->getResourceOwner()->getIdentifier(),
            $authorizationEndpoint->getRequestedScopes(),
            $requestData['redirect_uri'] ?? null
        );
        return ['code' => $this->authorizationCode->getCode()];
    }

    public function getDefaultResponseMode(): string
    {
        return 'query';
    }

    public function getUnsupportedResponseModes(): array
    {
        return [];
    }

    public function getGrantTypes(): array
    {
        return ['authorization_code'];
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

        $this->authorizationCode = $this->authorizationCodeStorage->get($code);

        /**
         * ensure that the authorization code was issued to the authenticated
         * confidential client, or if the client is public, ensure that the
         * code was issued to "client_id" in the request,
         */
        if (!$this->authorizationCode ||
            $this->authorizationCode->getClientIdentifier() !== $tokenEndpoint->getClient()->getIdentifier()) {
            throw new OAuthException('invalid_grant',
                'The request includes the invalid parameter code.',
                'https://tools.ietf.org/html/rfc7636#section-4.4');
        }

        $this->authorizationCodeStorage->revoke($code);

        /**
         * verify that the authorization code is valid
         */
        if ($this->authorizationCodeStorage->hasExpired($this->authorizationCode)) {
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
        if ($this->authorizationCode->getRedirectUri()) {
            if (empty($requestData['redirect_uri'])) {
                throw new OAuthException('invalid_request',
                    'The request is missing the required parameter redirect_uri',
                    'https://tools.ietf.org/html/rfc7636#section-4.1');
            }
            if ($requestData['redirect_uri'] !== $this->authorizationCode->getRedirectUri()) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter redirect_uri',
                    'https://tools.ietf.org/html/rfc7636#section-4.1');
            }
        }

        $responseData = $this->issueTokens(
            $this->authorizationCode->getScopes(),
            $this->authorizationCode->getClientIdentifier(),
            $this->authorizationCode->getResourceOwnerIdentifier(),
            $this->authorizationCode->getCode());

        if(is_null($this->authorizationCode->getRequestedScopes()) ||
            array_diff($this->authorizationCode->getRequestedScopes(), $this->authorizationCode->getScopes())) {
            $responseData['scope'] = implode(' ', $this->authorizationCode->getScopes());
        }

        return $responseData;
    }

    /**
     * @return AuthorizationCode
     */
    protected function getAuthorizationCode(): AuthorizationCode
    {
        return $this->authorizationCode;
    }
}
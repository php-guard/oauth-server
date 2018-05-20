<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 12/03/2018
 * Time: 15:16
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Exceptions\OAuthException;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;
use OAuth2\Helper;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\AccessTokenStorageInterface;
use OAuth2\Storages\RefreshTokenStorageInterface;
use OAuth2\Storages\ResourceOwnerStorageInterface;


/**
 * Class ResourceOwnerPasswordCredentialsFlow
 * @package OAuth2\AuthorizationGrantTypes\Flows
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3.3
 * The resource owner password credentials (i.e., username and password)
 * can be used directly as an authorization grant to obtain an access
 * token.  The credentials should only be used when there is a high
 * degree of trust between the resource owner and the client (e.g., the
 * client is part of the device operating system or a highly privileged
 * application), and when other authorization grant types are not
 * available (such as an authorization code).
 *
 * Even though this grant type requires direct client access to the
 * resource owner credentials, the resource owner credentials are used
 * for a single request and are exchanged for an access token.  This
 * grant type can eliminate the need for the client to store the
 * resource owner credentials for future use, by exchanging the
 * credentials with a long-lived access token or refresh token.
 *
 * @see https://tools.ietf.org/html/rfc6749#section-4.3
 * The resource owner password credentials grant type is suitable in
 * cases where the resource owner has a trust relationship with the
 * client, such as the device operating system or a highly privileged
 * application.  The authorization server should take special care when
 * enabling this grant type and only allow it when other flows are not
 * viable.
 *
 * This grant type is suitable for clients capable of obtaining the
 * resource owner's credentials (username and password, typically using
 * an interactive form).  It is also used to migrate existing clients
 * using direct authentication schemes such as HTTP Basic or Digest
 * authentication to OAuth by converting the stored credentials to an
 * access token.
 */
class ResourceOwnerPasswordCredentialsFlow extends AbstractGrantType implements FlowInterface
{
    /**
     * @var ResourceOwnerStorageInterface
     */
    private $resourceOwnerStorage;
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;

    public function __construct(ScopePolicyManager $scopePolicyManager,
                                ResourceOwnerStorageInterface $resourceOwnerStorage,
                                AccessTokenStorageInterface $accessTokenStorage,
                                RefreshTokenStorageInterface $refreshTokenStorage)
    {
        parent::__construct($accessTokenStorage, $refreshTokenStorage);
        $this->resourceOwnerStorage = $resourceOwnerStorage;
        $this->scopePolicyManager = $scopePolicyManager;
    }

    public function getResponseTypes(): array
    {
        return [];
    }

    public function getGrantTypes(): array
    {
        return ['password'];
    }

    /**
     * @param TokenEndpoint $tokenEndpoint
     * @param array $requestData
     * @return array
     * @throws OAuthException
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.2
     * The client makes a request to the token endpoint by adding the
     * following parameters using the "application/x-www-form-urlencoded"
     * format per Appendix B with a character encoding of UTF-8 in the HTTP
     * request entity-body:
     *
     * grant_type
     * REQUIRED.  Value MUST be set to "password".
     *
     * username
     * REQUIRED.  The resource owner username.
     *
     * password
     * REQUIRED.  The resource owner password.
     *
     * scope
     * OPTIONAL.  The scope of the access request as described by
     * Section 3.3.
     *
     * If the client type is confidential or the client was issued client
     * credentials (or assigned other authentication requirements), the
     * client MUST authenticate with the authorization server as described
     * in Section 3.2.1.
     *
     * For example, the client makes the following HTTP request using
     * transport-layer security (with extra line breaks for display purposes
     * only):
     *
     * POST /token HTTP/1.1
     * Host: server.example.com
     * Authorization: Basic czZCaGRSa3F0MzpnWDFmQmF0M2JW
     * Content-Type: application/x-www-form-urlencoded
     *
     * grant_type=password&username=johndoe&password=A3ddj3w
     *
     * The authorization server MUST:
     *
     * o  require client authentication for confidential clients or for any
     * client that was issued client credentials (or with other
     * authentication requirements),
     *
     * o  authenticate the client if client authentication is included, and
     *
     * o  validate the resource owner password credentials using its
     * existing password validation algorithm.
     *
     * Since this access token request utilizes the resource owner's
     * password, the authorization server MUST protect the endpoint against
     * brute force attacks (e.g., using rate-limitation or generating
     * alerts).
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.3.3
     * If the access token request is valid and authorized, the
     * authorization server issues an access token and optional refresh
     * token as described in Section 5.1.  If the request failed client
     * authentication or is invalid, the authorization server returns an
     * error response as described in Section 5.2.
     */
    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        if (empty($requestData['username'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter username.',
                'https://tools.ietf.org/html/rfc7636#section-4.3');
        }

        if (empty($requestData['password'])) {
            throw new OAuthException('invalid_request',
                'The request is missing the required parameter password.',
                'https://tools.ietf.org/html/rfc7636#section-4.3');
        }

        $client = $tokenEndpoint->getClient();

        $scopes = $this->scopePolicyManager->getScopes($client, $requestData['scope'] ?? null, $requestedScopes);
        $this->scopePolicyManager->verifyScopes($client, $scopes);

        $resourceOwnerIdentifier = $this->resourceOwnerStorage->validateCredentials(
            $requestData['username'], $requestData['password']);

        if (is_null($resourceOwnerIdentifier)) {
            throw new OAuthException('invalid_grant',
                'The provider authorization grant is invalid. Resource owner credentials invalid.',
                'https://tools.ietf.org/html/rfc7636#section-4.3');
        }

        $responseData = $this->issueTokens($scopes, $client->getIdentifier(), $resourceOwnerIdentifier);

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

    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
        throw new \BadMethodCallException();
    }

    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        throw new \BadMethodCallException();
    }

    public function getDefaultResponseMode(): string
    {
        throw new \BadMethodCallException();
    }

    public function getUnsupportedResponseModes(): array
    {
        throw new \BadMethodCallException();
    }
}
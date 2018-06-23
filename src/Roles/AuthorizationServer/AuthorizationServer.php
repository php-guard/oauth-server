<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/03/2018
 * Time: 15:55
 */

namespace OAuth2\Roles\AuthorizationServer;


use OAuth2\ClientAuthentication\ClientAuthenticationMethodManager;
use OAuth2\ClientAuthentication\ClientSecretBasicAuthenticationMethod;
use OAuth2\ClientAuthentication\ClientSecretPostAuthenticationMethod;
use OAuth2\Config;
use OAuth2\Endpoints\Authorization\AuthorizationRequestBuilder;
use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\EndpointInterface;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow;
use OAuth2\AuthorizationGrantTypes\Flows\ClientCredentialsFlow;
use OAuth2\AuthorizationGrantTypes\Flows\FlowManager;
use OAuth2\AuthorizationGrantTypes\Flows\ImplicitFlow;
use OAuth2\AuthorizationGrantTypes\Flows\ResourceOwnerPasswordCredentialsFlow;
use OAuth2\AuthorizationGrantTypes\GrantTypeManager;
use OAuth2\AuthorizationGrantTypes\RefreshTokenGrantType;
use OAuth2\Endpoints\TokenRevocationEndpoint;
use OAuth2\Extensions\PKCE\Endpoints\Authorization\AuthorizationRequestBuilder as PKCEAuthorizationRequestBuilder;
use OAuth2\Extensions\PKCE\Storages\AuthorizationCodeStorageInterface as PKCEAuthorizationCodeStorageInterface;
use OAuth2\ResponseModes\FragmentResponseMode;
use OAuth2\ResponseModes\QueryResponseMode;
use OAuth2\ResponseModes\ResponseModeManager;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeManager;
use OAuth2\Roles\AuthorizationServerInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;


class AuthorizationServer implements AuthorizationServerInterface
{
    protected $authorizationEndpoint;
    protected $tokenEndpoint;
    protected $responseTypeManager;
    protected $storageManager;
    protected $scopePolicyManager;
    protected $grantTypeManager;
    protected $clientAuthenticationMethodManager;
    protected $responseModeManager;
    protected $flowManager;
    protected $tokenRevocationEndpoint;

    public function __construct(Config $config,
                                StorageManager $storageManager,
                                ScopePolicyManager $scopePolicyManager,
                                EndUserInterface $authorizationServerEndUser)
    {
        $this->responseTypeManager = new ResponseTypeManager();
        $this->grantTypeManager = new GrantTypeManager();
        $this->storageManager = $storageManager;
        $this->scopePolicyManager = $scopePolicyManager;

        $this->clientAuthenticationMethodManager = new ClientAuthenticationMethodManager($this->storageManager->getClientStorage());
        $this->clientAuthenticationMethodManager->addClientAuthenticationMethod('client_secret_basic',
            new ClientSecretBasicAuthenticationMethod($this->storageManager->getClientStorage()));
        $this->clientAuthenticationMethodManager->addClientAuthenticationMethod('client_secret_post',
            new ClientSecretPostAuthenticationMethod($this->storageManager->getClientStorage()));

//        $queryResponseMode = new QueryResponseMode();
        $this->responseModeManager = new ResponseModeManager();
        $this->responseModeManager->addResponseMode('query', new QueryResponseMode());
        $this->responseModeManager->addResponseMode('fragment', new FragmentResponseMode());

        // response_type : code
        // grant_type : authorization_code

        //PKCE
//        $authorizationCodeStorage = $this->storageManager->getAuthorizationCodeStorage();
//        if ($authorizationCodeStorage instanceof PKCEAuthorizationCodeStorageInterface) {
//            $authorizationCodeFlow = new \OAuth2\Extensions\PKCE\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow(
//                $config,
//                $authorizationCodeStorage,
//                $this->storageManager->getAccessTokenStorage(),
//                $this->storageManager->getRefreshTokenStorage()
//            );
//        }

        //SANS PKCE
        $authorizationCodeFlow = new AuthorizationCodeFlow(
            $config,
            $this->storageManager->getAuthorizationCodeStorage(),
            $this->storageManager->getAccessTokenStorage(),
            $this->storageManager->getRefreshTokenStorage()
        );

        // response_type : token
        $implicitFlow = new ImplicitFlow(
            $this->storageManager->getAccessTokenStorage(),
            $this->storageManager->getRefreshTokenStorage()
        );

        // grant_type : password
        $resourceOwnerPasswordCredentialsFlow = new ResourceOwnerPasswordCredentialsFlow(
            $this->scopePolicyManager,
            $this->storageManager->getResourceOwnerStorage(),
            $this->storageManager->getAccessTokenStorage(),
            $this->storageManager->getRefreshTokenStorage());

        // grant_type : client_credentials
        $clientCredentialsFlow = new ClientCredentialsFlow(
            $this->scopePolicyManager,
            $this->storageManager->getAccessTokenStorage(),
            $this->storageManager->getRefreshTokenStorage()
        );

        // grant_type : refresh_token
        $refreshTokenGrantType = new RefreshTokenGrantType(
            $this->storageManager->getAccessTokenStorage(),
            $this->storageManager->getRefreshTokenStorage(),
            $config,
            $this->scopePolicyManager
        );

        $this->flowManager = new FlowManager($this->responseTypeManager, $this->grantTypeManager);
        $this->flowManager->addFlow($authorizationCodeFlow);
        $this->flowManager->addFlow($implicitFlow);
        $this->flowManager->addFlow($resourceOwnerPasswordCredentialsFlow);
        $this->flowManager->addFlow($clientCredentialsFlow);

        $this->grantTypeManager->addGrantType('refresh_token', $refreshTokenGrantType);

        // PKCE
//        $authorizationRequestBuilder = new PKCEAuthorizationRequestBuilder(
//            $this->storageManager->getClientStorage(),
//            $this->responseTypeManager,
//            $this->responseModeManager,
//            $this->scopePolicyManager
//        );

        // SANS PKCE
        $authorizationRequestBuilder = new AuthorizationRequestBuilder(
            $this->storageManager->getClientStorage(),
            $this->responseTypeManager,
            $this->responseModeManager,
            $this->scopePolicyManager
        );


        $this->authorizationEndpoint = new AuthorizationEndpoint($authorizationRequestBuilder, $authorizationServerEndUser);

        $this->tokenEndpoint = new TokenEndpoint(
            $this->grantTypeManager,
            $this->clientAuthenticationMethodManager);

        $this->tokenRevocationEndpoint = new TokenRevocationEndpoint(
            $this->clientAuthenticationMethodManager,
            $this->storageManager);
    }

    /**
     * @return AuthorizationEndpoint
     */
    public function getAuthorizationEndpoint(): EndpointInterface
    {
        return $this->authorizationEndpoint;
    }

    /**
     * @return TokenEndpoint
     */
    public function getTokenEndpoint(): EndpointInterface
    {
        return $this->tokenEndpoint;
    }

    /**
     * @return TokenRevocationEndpoint
     */
    public function getTokenRevocationEndpoint(): TokenRevocationEndpoint
    {
        return $this->tokenRevocationEndpoint;
    }

    /**
     * @return bool
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2.1
     *
     *  Endpoint Request Confidentiality
     *
     *     The redirection endpoint SHOULD require the use of TLS as described
     * in Section 1.6 when the requested response type is "code" or "token",
     * or when the redirection request will result in the transmission of
     * sensitive credentials over an open network.  This specification does
     * not mandate the use of TLS because at the time of this writing,
     * requiring clients to deploy TLS is a significant hurdle for many
     * client developers.  If TLS is not available, the authorization server
     * SHOULD warn the resource owner about the insecure endpoint prior to
     * redirection (e.g., display a message during the authorization
     * request).
     *
     * Lack of transport-layer security can have a severe impact on the
     * security of the client and the protected resources it is authorized
     * to access.  The use of transport-layer security is particularly
     * critical when the authorization process is used as a form of
     * delegated end-user authentication by the client (e.g., third-party
     * sign-in service).
     * @deprecated
     */
    public function isSecure()
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443;
    }
}
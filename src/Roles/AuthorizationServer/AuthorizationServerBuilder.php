<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 22:25
 */

namespace OAuth2\Roles\AuthorizationServer;


use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeManager;
use OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow;
use OAuth2\AuthorizationGrantTypes\Flows\ClientCredentialsFlow;
use OAuth2\AuthorizationGrantTypes\Flows\FlowManager;
use OAuth2\AuthorizationGrantTypes\Flows\ImplicitFlow;
use OAuth2\AuthorizationGrantTypes\Flows\ResourceOwnerPasswordCredentialsFlow;
use OAuth2\AuthorizationGrantTypes\GrantTypeManager;
use OAuth2\AuthorizationGrantTypes\RefreshTokenGrantType;
use OAuth2\ClientAuthentication\ClientAuthenticationMethodManager;
use OAuth2\ClientAuthentication\ClientSecretBasicAuthenticationMethod;
use OAuth2\ClientAuthentication\ClientSecretPostAuthenticationMethod;
use OAuth2\Config;
use OAuth2\Endpoints\Authorization\AuthorizationRequestBuilder;
use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Endpoints\TokenRevocationEndpoint;
use OAuth2\ResponseModes\FragmentResponseMode;
use OAuth2\ResponseModes\QueryResponseMode;
use OAuth2\ResponseModes\ResponseModeManager;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;

class AuthorizationServerBuilder
{
    /**
     * @var Config
     */
    private $config;
    /**
     * @var StorageManager
     */
    private $storageManager;
    /**
     * @var ScopePolicyManager
     */
    private $scopePolicyManager;
    /**
     * @var EndUserInterface
     */
    private $endUser;

    private $clientAuthenticationMethodManager;
    private $responseTypeManager;
    private $grantTypeManager;
    private $responseModeManager;
    private $flowManager;

    private $authorizationRequestBuilder;

    public function __construct(Config $config,
                                StorageManager $storageManager,
                                ScopePolicyManager $scopePolicyManager,
                                EndUserInterface $endUser
    )
    {
        $this->config = $config;
        $this->storageManager = $storageManager;
        $this->scopePolicyManager = $scopePolicyManager;
        $this->endUser = $endUser;

        $this->responseTypeManager = new ResponseTypeManager();

        $this->grantTypeManager = new GrantTypeManager();
        $this->grantTypeManager->setGrantType('refresh_token', new RefreshTokenGrantType(
            $this->storageManager->getAccessTokenStorage(),
            $this->storageManager->getRefreshTokenStorage(),
            $config,
            $this->scopePolicyManager
        ));

        $this->responseModeManager = new ResponseModeManager();
        $this->responseModeManager
            ->setResponseMode('query', new QueryResponseMode())
            ->setResponseMode('fragment', new FragmentResponseMode());

        $this->flowManager = new FlowManager($this->responseTypeManager, $this->grantTypeManager);
        $this->flowManager
            ->addFlow('authorization_code', new AuthorizationCodeFlow(
                $config,
                $this->storageManager->getAuthorizationCodeStorage(),
                $this->storageManager->getAccessTokenStorage(),
                $this->storageManager->getRefreshTokenStorage()
            ))
            ->addFlow('implicit', new ImplicitFlow(
                $this->storageManager->getAccessTokenStorage(),
                $this->storageManager->getRefreshTokenStorage()
            ))
            ->addFlow('resource_owner_password_credentials', new ResourceOwnerPasswordCredentialsFlow(
                $this->scopePolicyManager,
                $this->storageManager->getResourceOwnerStorage(),
                $this->storageManager->getAccessTokenStorage(),
                $this->storageManager->getRefreshTokenStorage()))
            ->addFlow('client_credentials', new ClientCredentialsFlow(
                $this->scopePolicyManager,
                $this->storageManager->getAccessTokenStorage(),
                $this->storageManager->getRefreshTokenStorage()
            ));

        $this->clientAuthenticationMethodManager = new ClientAuthenticationMethodManager($storageManager->getClientStorage());
        $this->clientAuthenticationMethodManager
            ->setClientAuthenticationMethod('client_secret_basic', new ClientSecretBasicAuthenticationMethod(
                $this->storageManager->getClientStorage()
            ))
            ->setClientAuthenticationMethod('client_secret_post', new ClientSecretPostAuthenticationMethod(
                $this->storageManager->getClientStorage()
            ));

        $this->authorizationRequestBuilder = new AuthorizationRequestBuilder(
            $this->storageManager->getClientStorage(),
            $this->responseTypeManager,
            $this->responseModeManager,
            $this->scopePolicyManager
        );
    }

    public function build(): AuthorizationServer
    {
        $authorizationEndpoint = new AuthorizationEndpoint($this->authorizationRequestBuilder, $this->endUser);

        $tokenEndpoint = new TokenEndpoint(
            $this->grantTypeManager,
            $this->clientAuthenticationMethodManager);

        $tokenRevocationEndpoint = new TokenRevocationEndpoint(
            $this->clientAuthenticationMethodManager,
            $this->storageManager);

        return new AuthorizationServer($authorizationEndpoint, $tokenEndpoint, $tokenRevocationEndpoint);
    }

    /**
     * @return ClientAuthenticationMethodManager
     */
    public function getClientAuthenticationMethodManager(): ClientAuthenticationMethodManager
    {
        return $this->clientAuthenticationMethodManager;
    }

    /**
     * @return ResponseModeManager
     */
    public function getResponseModeManager(): ResponseModeManager
    {
        return $this->responseModeManager;
    }

    /**
     * @param AuthorizationRequestBuilder $authorizationRequestBuilder
     * @return AuthorizationServerBuilder
     */
    public function setAuthorizationRequestBuilder(AuthorizationRequestBuilder $authorizationRequestBuilder): self
    {
        $this->authorizationRequestBuilder = $authorizationRequestBuilder;
        return $this;
    }

    /**
     * @return FlowManager
     */
    public function getFlowManager(): FlowManager
    {
        return $this->flowManager;
    }

    /**
     * @return StorageManager
     */
    public function getStorageManager(): StorageManager
    {
        return $this->storageManager;
    }

    /**
     * @return ScopePolicyManager
     */
    public function getScopePolicyManager(): ScopePolicyManager
    {
        return $this->scopePolicyManager;
    }

    /**
     * @return Config
     */
    public function getConfig(): Config
    {
        return $this->config;
    }

    /**
     * @return EndUserInterface
     */
    public function getEndUser(): EndUserInterface
    {
        return $this->endUser;
    }

    /**
     * @return ResponseTypeManager
     */
    public function getResponseTypeManager(): ResponseTypeManager
    {
        return $this->responseTypeManager;
    }

    /**
     * @return GrantTypeManager
     */
    public function getGrantTypeManager(): GrantTypeManager
    {
        return $this->grantTypeManager;
    }

    /**
     * @return AuthorizationRequestBuilder
     */
    public function getAuthorizationRequestBuilder(): AuthorizationRequestBuilder
    {
        return $this->authorizationRequestBuilder;
    }
}
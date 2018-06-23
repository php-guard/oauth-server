<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 21/04/2018
 * Time: 18:45
 */

namespace OAuth2;


use OAuth2\Roles\AuthorizationServer\AuthorizationServer;
use OAuth2\Roles\AuthorizationServer\EndUserInterface;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\FormEncodedBodyParameter;
use OAuth2\Roles\ResourceServer\BearerAuthenticationMethods\URIQueryParameter;
use OAuth2\Roles\ResourceServer\ResourceServer;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\StorageManager;

class OAuthServer
{
    private $authorizationServer;
    private $resourceServer;

    public function __construct(AuthorizationServer $authorizationServer,
                                ResourceServer $resourceServer)
    {
        $this->authorizationServer = $authorizationServer;
        $this->resourceServer = $resourceServer;
    }

    /**
     * @return AuthorizationServer
     */
    public function getAuthorizationServer(): AuthorizationServer
    {
        return $this->authorizationServer;
    }

    /**
     * @return ResourceServer
     */
    public function getResourceServer(): ResourceServer
    {
        return $this->resourceServer;
    }


}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 16/06/2018
 * Time: 15:28
 */

namespace OAuth2\Extensions\PKCE;


use OAuth2\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow;
use OAuth2\Extensions\ExtensionInterface;
use OAuth2\Extensions\PKCE\AuthorizationGrantTypes\Flows\AuthorizationCodeFlow as PKCEAuthorizationCodeFlow;
use OAuth2\Extensions\PKCE\Endpoints\Authorization\AuthorizationRequestBuilder as PKCEAuthorizationRequestBuilder;
use OAuth2\Extensions\PKCE\Storages\AuthorizationCodeStorageInterface as PKCEAuthorizationCodeStorageInterface;
use OAuth2\Roles\AuthorizationServer\AuthorizationServerBuilder;

class PKCEExtension implements ExtensionInterface
{
    public function extendAuthorizationServerBuilder(AuthorizationServerBuilder $builder)
    {
        $builder->setAuthorizationRequestBuilder(new PKCEAuthorizationRequestBuilder(
            $builder->getStorageManager()->getClientStorage(),
            $builder->getResponseTypeManager(),
            $builder->getResponseModeManager(),
            $builder->getScopePolicyManager()
        ));

        $authorizationCodeStorage = $builder->getStorageManager()->getAuthorizationCodeStorage();
        if(!$authorizationCodeStorage instanceof PKCEAuthorizationCodeStorageInterface) {
            throw new \InvalidArgumentException('Authorization code storage must be an instance of "' . PKCEAuthorizationCodeStorageInterface::class . '"');
        }

        $authorizationCodeFlow = $builder->getFlowManager()->getFlow('authorization_code');
        if (!$authorizationCodeFlow instanceof AuthorizationCodeFlow) {
            throw new \InvalidArgumentException('Flow with key "authorization_code" must be an instance of "' . AuthorizationCodeFlow::class . '"');
        }

        $builder->getFlowManager()->addFlow('authorization_code', new PKCEAuthorizationCodeFlow(
            $authorizationCodeFlow,
            $authorizationCodeStorage
        ));
    }
}
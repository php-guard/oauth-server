<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 23/06/2018
 * Time: 18:07
 */

namespace OAuth2\Extensions;


use OAuth2\OAuthServer;
use OAuth2\OAuthServerBuilder;
use OAuth2\Roles\AuthorizationServer\AuthorizationServerBuilder;

interface ExtensionInterface
{
    public function extendAuthorizationServerBuilder(AuthorizationServerBuilder $builder);
//    public function load(OAuthServer $server);
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 23/06/2018
 * Time: 18:07
 */

namespace OAuth2\Extensions;


use OAuth2\OAuthServerBuilder;

interface ExtensionInterface
{
    public function load(OAuthServerBuilder $builder);
}
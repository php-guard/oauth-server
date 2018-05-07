<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 17/03/2018
 * Time: 13:47
 */

namespace OAuth2\Extensions\OpenID\Storages;


use OAuth2\Credentials\AuthorizationCodeInterface;

/**
 * Interface AuthorizationCodeStorageInterface
 * @package OAuth2\Extensions\OpenID\Storages
 * @deprecated
 */
interface AuthorizationCodeStorageInterface extends \OAuth2\Storages\AuthorizationCodeStorageInterface
{
    function generate(string $scope, string $clientIdentifier, string $resourceOwnerIdentifier,
                    ?string $requestedScope, ?string $redirectUri, ?string $idToken = null): AuthorizationCodeInterface;
}
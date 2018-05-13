<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 17/03/2018
 * Time: 13:49
 */

namespace OAuth2\Extensions\OpenID\Credentials;


/**
 * Interface AuthorizationCodeInterface
 * @package OAuth2\Extensions\OpenID\Credentials
 * @deprecated
 */
interface AuthorizationCodeInterface extends \OAuth2\Credentials\AuthorizationCodeInterface
{
    function getIdToken(): ?string;
}
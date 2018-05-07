<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 20:51
 */

namespace OAuth2\Extensions\PKCE\Storages;


use OAuth2\Credentials\AuthorizationCodeInterface;
use OAuth2\Extensions\PKCE\Credentials\CodeChallengeInterface;

interface AuthorizationCodeStorageInterface extends \OAuth2\Storages\AuthorizationCodeStorageInterface
{
    function getCodeChallenge(AuthorizationCodeInterface $authorizationCode): ?CodeChallengeInterface;

    function associate(CodeChallengeInterface $codeChallenge, AuthorizationCodeInterface $authorizationCode);
}
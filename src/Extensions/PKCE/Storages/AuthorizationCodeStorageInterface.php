<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 20:51
 */

namespace OAuth2\Extensions\PKCE\Storages;


use OAuth2\Credentials\AuthorizationCodeInterface;


interface AuthorizationCodeStorageInterface extends \OAuth2\Storages\AuthorizationCodeStorageInterface
{
    /**
     * @param AuthorizationCodeInterface $authorizationCode
     * @param string $codeChallenge
     * @param string $codeChallengeMethod
     * @return mixed
     * TODO utiliser un builder
     */
    public function setCodeChallenge(AuthorizationCodeInterface $authorizationCode, string $codeChallenge,
                                     string $codeChallengeMethod = 'plain');

}
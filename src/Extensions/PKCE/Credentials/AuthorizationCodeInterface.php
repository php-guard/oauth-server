<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 20:50
 */

namespace OAuth2\Extensions\PKCE\Credentials;


interface AuthorizationCodeInterface extends \OAuth2\Credentials\AuthorizationCodeInterface
{
    public function getCodeChallenge(): ?string;

    public function setCodeChallenge(?string $codeChallenge): void;

    public function getCodeChallengeMethod(): ?string;

    public function setCodeChallengeMethod(?string $codeChallengeMethod): void;
}
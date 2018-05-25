<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 20:56
 */

namespace OAuth2\Extensions\PKCE\Credentials;


interface CodeChallengeInterface
{
public function getCodeChallenge(): string;

public function getCodeChallengeMethod(): string;
}
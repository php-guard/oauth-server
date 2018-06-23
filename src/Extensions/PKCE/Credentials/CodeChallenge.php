<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 21:17
 */

namespace OAuth2\Extensions\PKCE\Credentials;


/**
 * Class CodeChallenge
 * @package OAuth2\Extensions\PKCE\Credentials
 * @deprecated
 */
class CodeChallenge implements CodeChallengeInterface
{
    protected $codeChallenge;
    protected $codeChallengeMethod;

    public function __construct(string $codeChallenge, string $codeChallengeMethod)
    {
        $this->codeChallenge = $codeChallenge;
        $this->codeChallengeMethod = $codeChallengeMethod;
    }

    /**
     * @return mixed
     */
    public function getCodeChallenge(): string
    {
        return $this->codeChallenge;
    }

    /**
     * @return string
     */
    public function getCodeChallengeMethod(): string
    {
        return $this->codeChallengeMethod;
    }

}
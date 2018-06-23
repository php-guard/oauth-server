<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 21:05
 */

namespace OAuth2\Extensions\PKCE\Endpoints\Authorization;


class AuthorizationRequest extends \OAuth2\Endpoints\Authorization\AuthorizationRequest
{
    /**
     * @var string
     */
    private $codeChallenge;
    /**
     * @var string
     */
    private $codeChallengeMethod;

    public function __construct(\OAuth2\Endpoints\Authorization\AuthorizationRequest $authorizationRequest,
                                string $codeChallenge, string $codeChallengeMethod = 'plain')
    {
        parent::__construct($authorizationRequest->getData(),
            $authorizationRequest->getResourceOwner(),
            $authorizationRequest->getClient(),
            $authorizationRequest->getRedirectUri(),
            $authorizationRequest->getResponseType(),
            $authorizationRequest->getResponseMode(),
            $authorizationRequest->getScopes(),
            $authorizationRequest->getRequestedScopes(),
            $authorizationRequest->getState());

        $this->codeChallenge = $codeChallenge;
        $this->codeChallengeMethod = $codeChallengeMethod;
    }

    /**
     * @return string
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
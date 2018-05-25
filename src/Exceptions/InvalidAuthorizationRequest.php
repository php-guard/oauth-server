<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 25/05/2018
 * Time: 23:44
 */

namespace OAuth2\Exceptions;


use OAuth2\ResponseModes\ResponseModeInterface;
use Psr\Http\Message\UriInterface;

class InvalidAuthorizationRequest extends \Exception
{
    /**
     * @var OAuthException
     */
    private $oauthException;
    /**
     * @var UriInterface
     */
    private $redirectUri;
    /**
     * @var ResponseModeInterface
     */
    private $responseMode;
    /**
     * @var null|string
     */
    private $state;

    public function __construct(OAuthException $oauthException,
                                UriInterface $redirectUri,
                                ResponseModeInterface $responseMode,
                                ?string $state)
    {
        $this->oauthException = $oauthException;
        $this->redirectUri = $redirectUri;
        $this->responseMode = $responseMode;
        $this->state = $state;
    }

    /**
     * @return OAuthException
     */
    public function getOauthException(): OAuthException
    {
        return $this->oauthException;
    }

    /**
     * @return UriInterface
     */
    public function getRedirectUri(): UriInterface
    {
        return $this->redirectUri;
    }

    /**
     * @return ResponseModeInterface
     */
    public function getResponseMode(): ResponseModeInterface
    {
        return $this->responseMode;
    }

    /**
     * @return null|string
     */
    public function getState(): ?string
    {
        return $this->state;
    }


}
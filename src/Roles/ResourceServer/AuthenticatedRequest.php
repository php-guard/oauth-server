<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 27/05/2018
 * Time: 17:48
 */

namespace OAuth2\Roles\ResourceServer;


use OAuth2\Credentials\AccessTokenInterface;
use OAuth2\Roles\ClientTypes\RegisteredClientInterface;
use OAuth2\Roles\ResourceOwnerInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthenticatedRequest
{
    /**
     * @var ServerRequestInterface
     */
    private $request;
    /**
     * @var RegisteredClientInterface
     */
    private $client;
    /**
     * @var null|ResourceOwnerInterface
     */
    private $resourceOwner;
    /**
     * @var AccessTokenInterface
     */
    private $accessToken;

    public function __construct(ServerRequestInterface $request,
                                RegisteredClientInterface $client,
                                ?ResourceOwnerInterface $resourceOwner,
                                AccessTokenInterface $accessToken)
    {
        $this->request = $request;
        $this->client = $client;
        $this->resourceOwner = $resourceOwner;
        $this->accessToken = $accessToken;
    }

    /**
     * @return ServerRequestInterface
     */
    public function getRequest(): ServerRequestInterface
    {
        return $this->request;
    }

    /**
     * @return RegisteredClientInterface
     */
    public function getClient(): RegisteredClientInterface
    {
        return $this->client;
    }

    /**
     * @return null|ResourceOwnerInterface
     */
    public function getResourceOwner(): ?ResourceOwnerInterface
    {
        return $this->resourceOwner;
    }

    /**
     * @return array
     */
    public function getScopes(): array
    {
        return $this->accessToken->getScopes();
    }

    /**
     * @return AccessTokenInterface
     */
    public function getAccessToken(): AccessTokenInterface
    {
        return $this->accessToken;
    }
}
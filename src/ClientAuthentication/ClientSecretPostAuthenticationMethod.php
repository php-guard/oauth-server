<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 16:59
 */

namespace OAuth2\ClientAuthentication;


use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\Clients\ConfidentialClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientSecretPostAuthenticationMethod implements ClientAuthenticationMethodInterface
{
    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;

    public function __construct(ClientStorageInterface $clientStorage)
    {
        $this->clientStorage = $clientStorage;
    }

    public function support(ServerRequestInterface $request, array $requestData): bool
    {
        return !empty($requestData['client_id']) && !empty($requestData['client_secret']);
    }

    public function authenticate(ServerRequestInterface $request, array $requestData): ?ClientInterface
    {
        $client = $this->clientStorage->get($requestData['client_id']);
        if ($client instanceof ConfidentialClient && $client->getPassword() == $requestData['client_secret']) {
            return $client;
        }
        return null;
    }
}
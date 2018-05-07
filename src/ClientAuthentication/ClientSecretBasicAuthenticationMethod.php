<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 16:58
 */

namespace OAuth2\ClientAuthentication;


use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\Clients\ConfidentialClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientSecretBasicAuthenticationMethod implements ClientAuthenticationMethodInterface
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
        $header = $request->getHeader('Authorization')[0] ?? null;
        return strpos($header, 'Basic') === 0;
    }

    public function authenticate(ServerRequestInterface $request, array $requestData): ?ClientInterface
    {
        $header = $request->getHeader('Authorization')[0];
        $token = explode(' ', $header)[1] ?? null;
        if ($token) {
            $credentials = explode(':', base64_decode($token));
            if (count($credentials) == 2) {
                $client = $this->clientStorage->get($credentials[0]);
                if ($client instanceof ConfidentialClient && $client->getPassword() === $credentials[1]) {
                    return $client;
                }
            }
        }
        return null;
    }
}
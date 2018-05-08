<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 17:00
 */

namespace OAuth2\ClientAuthentication;


use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\Clients\RegisteredClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

class ClientAuthenticationMethodManager
{
    protected $clientAuthenticationMethods = [];
    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;

    public function __construct(ClientStorageInterface $clientStorage)
    {
        $this->clientStorage = $clientStorage;
    }

    public function addClientAuthenticationMethod(string $identifier, ClientAuthenticationMethodInterface $clientAuthenticationMethod)
    {
        $this->clientAuthenticationMethods[$identifier] = $clientAuthenticationMethod;
    }

    public function getClientAuthenticationMethod(string $identifier): ?ClientAuthenticationMethodInterface
    {
        return $this->clientAuthenticationMethods[$identifier] ?? null;
    }

    /**
     * authenticate the client if client authentication is included
     * @param ServerRequestInterface $request
     * @param array                  $requestData
     * @return RegisteredClient
     * @throws OAuthException
     */
    public function authenticate(ServerRequestInterface $request, array $requestData): RegisteredClient
    {
        /**
         * require client authentication for confidential clients or for any
         * client that was issued client credentials (or with other
         * authentication requirements)
         */

        /**
         * @var ClientAuthenticationMethodInterface $clientAuthenticationMethod
         */
        $clientAuthenticationMethodUsedIdentifier = null;
        $clientAuthenticationMethodUsed = null;

        foreach ($this->clientAuthenticationMethods as $identifier => $clientAuthenticationMethod) {
            if ($clientAuthenticationMethod->support($request, $requestData)) {
                if ($clientAuthenticationMethodUsedIdentifier) {
                    throw new OAuthException('invalid_request',
                        'The request utilizes more than one mechanism for authenticating the client.',
                        'https://tools.ietf.org/html/rfc6749#section-3.2.1');
                }
                $clientAuthenticationMethodUsedIdentifier = $identifier;
                $clientAuthenticationMethodUsed = $clientAuthenticationMethod;
            }
        }

        if ($clientAuthenticationMethodUsed) {
            if (!$client = $clientAuthenticationMethodUsed->authenticate($request, $requestData)) {
                throw new OAuthException('invalid_client',
                    'Client authentication failed. Unknown client.',
                    'https://tools.ietf.org/html/rfc6749#section-3.2.1');
            }
        } else {
            if (empty($requestData['client_id'])) {
                throw new OAuthException('invalid_request', 'The request is missing the required parameter client_id.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }

            if (!$client = $this->clientStorage->get($requestData['client_id'])) {
                throw new OAuthException('invalid_request', 'The request includes the invalid parameter client_id.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }

            if ($client->hasCredentials()) {
                throw new OAuthException('invalid_client', 'Client authentication failed. No client authentication included',
                    'https://tools.ietf.org/html/rfc6749#section-3.2.1');
            }

            $clientAuthenticationMethodUsedIdentifier = 'none';
        }

        $tokenEndpointAuthMethod = $client->getMetadata()->getTokenEndpointAuthMethod() ?: 'client_secret_basic';
        if ($tokenEndpointAuthMethod !== $clientAuthenticationMethodUsedIdentifier) {
            throw new OAuthException('invalid_client',
                'Client authentication failed. Unsupported authentication method.',
                'https://tools.ietf.org/html/rfc6749#section-3.2.1');

        }

        return $client;
    }
}
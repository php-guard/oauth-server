<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 17:00
 */

namespace OAuth2\ClientAuthentication;


use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class ClientAuthenticationMethodManager
 * @package OAuth2\ClientAuthentication
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.3
 * If the client type is confidential, the client and authorization
 * server establish a client authentication method suitable for the
 * security requirements of the authorization server.  The authorization
 * server MAY accept any form of client authentication meeting its
 * security requirements.
 *
 * Confidential clients are typically issued (or establish) a set of
 * client credentials used for authenticating with the authorization
 * server (e.g., password, public/private key pair).
 *
 * The authorization server MAY establish a client authentication method
 * with public clients.  However, the authorization server MUST NOT rely
 * on public client authentication for the purpose of identifying the
 * client.
 *
 * The client MUST NOT use more than one authentication method in each
 * request.
 *
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.2.1
 * Confidential clients or other clients issued client credentials MUST
 * authenticate with the authorization server as described in
 * Section 2.3 when making requests to the token endpoint.  Client
 * authentication is used for:
 *
 * o  Enforcing the binding of refresh tokens and authorization codes to
 * the client they were issued to.  Client authentication is critical
 * when an authorization code is transmitted to the redirection
 * endpoint over an insecure channel or when the redirection URI has
 * not been registered in full.
 *
 * o  Recovering from a compromised client by disabling the client or
 * changing its credentials, thus preventing an attacker from abusing
 * stolen refresh tokens.  Changing a single set of client
 * credentials is significantly faster than revoking an entire set of
 * refresh tokens.
 *
 * o  Implementing authentication management best practices, which
 * require periodic credential rotation.  Rotation of an entire set
 * of refresh tokens can be challenging, while rotation of a single
 * set of client credentials is significantly easier.
 *
 * A client MAY use the "client_id" request parameter to identify itself
 * when sending requests to the token endpoint.  In the
 * "authorization_code" "grant_type" request to the token endpoint, an
 * unauthenticated client MUST send its "client_id" to prevent itself
 * from inadvertently accepting a code intended for a client with a
 * different "client_id".  This protects the client from substitution of
 * the authentication code.  (It provides no additional security for the
 * protected resource.)
 */
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
     * @param ServerRequestInterface $request
     * @param array $requestData
     * @return RegisteredClient
     * @throws OAuthException
     */
    public function authenticate(ServerRequestInterface $request, array $requestData): ?RegisteredClient
    {
        /**
         * @var ClientAuthenticationMethodInterface $clientAuthenticationMethod
         */
        $clientAuthenticationMethodUsedIdentifier = null;
        $clientAuthenticationMethodUsed = null;

        foreach ($this->clientAuthenticationMethods as $identifier => $clientAuthenticationMethod) {
            if ($clientAuthenticationMethod->support($request, $requestData)) {
                /**
                 * @see https://tools.ietf.org/html/rfc6749#section-2.3
                 * The client MUST NOT use more than one authentication method in each
                 * request.
                 */
                if ($clientAuthenticationMethodUsedIdentifier) {
                    throw new OAuthException('invalid_request',
                        'The request utilizes more than one mechanism for authenticating the client.',
                        'https://tools.ietf.org/html/rfc6749#section-3.2.1');
                }

                $clientAuthenticationMethodUsedIdentifier = $identifier;
                $clientAuthenticationMethodUsed = $clientAuthenticationMethod;
            }
        }

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.2.1
         * Confidential clients or other clients issued client credentials MUST
         * authenticate with the authorization server as described in
         * Section 2.3 when making requests to the token endpoint.
         */
        if ($clientAuthenticationMethodUsed) {
            if (!$client = $clientAuthenticationMethodUsed->authenticate($request, $requestData)) {
                throw new OAuthException('invalid_client',
                    'Client authentication failed. Unknown client.',
                    'https://tools.ietf.org/html/rfc6749#section-3.2.1');
            }
        } else {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-3.2.1
             * A client MAY use the "client_id" request parameter to identify itself
             * when sending requests to the token endpoint.  In the
             * "authorization_code" "grant_type" request to the token endpoint, an
             * unauthenticated client MUST send its "client_id" to prevent itself
             * from inadvertently accepting a code intended for a client with a
             * different "client_id".  This protects the client from substitution of
             * the authentication code.  (It provides no additional security for the
             * protected resource.)
             */
            if (empty($requestData['client_id'])) {
                throw new OAuthException('invalid_request', 'The request is missing the required parameter client_id.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }

            if (!$client = $this->clientStorage->get($requestData['client_id'])) {
                throw new OAuthException('invalid_request', 'The request includes the invalid parameter client_id.',
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }

            /**
             * @see https://tools.ietf.org/html/rfc6749#section-3.2.1
             * Confidential clients or other clients issued client credentials MUST
             * authenticate with the authorization server as described in
             * Section 2.3 when making requests to the token endpoint.
             */
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
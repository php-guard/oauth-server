<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 08/03/2018
 * Time: 22:22
 */

namespace OAuth2\Endpoints;


use GuzzleHttp\Psr7\Response;
use OAuth2\ClientAuthentication\ClientAuthenticationMethodManager;
use OAuth2\Exceptions\OAuthException;
use OAuth2\GrantTypes\GrantTypeInterface;
use OAuth2\GrantTypes\GrantTypeManager;
use OAuth2\Roles\Clients\RegisteredClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

class TokenEndpoint implements EndpointInterface
{

    /**
     * @var ClientStorageInterface
     */
    private $clientStorage;
    /**
     * @var GrantTypeManager
     */
    private $grantTypeManager;
    /**
     * @var ClientAuthenticationMethodManager
     */
    private $clientAuthenticationMethodManager;

    /**
     * @var RegisteredClient|null
     */
    protected $client;
    /**
     * @var GrantTypeInterface|null
     */
    protected $grantType;

    public function __construct(ClientStorageInterface $clientStorage,
                                GrantTypeManager $grantTypeManager,
                                ClientAuthenticationMethodManager $clientAuthenticationMethodManager)
    {
        $this->clientStorage = $clientStorage;
        $this->grantTypeManager = $grantTypeManager;
        $this->clientAuthenticationMethodManager = $clientAuthenticationMethodManager;
    }

    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() === 'POST') {
            $requestData = $request->getParsedBody();
        } else {
            return new Response(404);
        }

        try {
            // Authentication Request Validation
            // The Authorization Server MUST validate all the OAuth 2.0 parameters according to the OAuth 2.0 specification.
            $this->verifyRequestData($request, $requestData);

            $responseData = $this->getGrantType()->handleAccessTokenRequest($this, $requestData);

        } catch (OAuthException $e) {
            /**
             * If the Authorization Server encounters any error, it MUST return an error response, per Section 5.2
             */
            $status = 400;
            $headers = ['Content-Type' => 'application/json'];
            if ($e->getError() === 'invalid_client') {
                $status = 401;
                if ($request->hasHeader('Authorization')) {
                    $headers['WWW-Authenticate'] = 'Basic';
                }
            }
            return new Response($status, $headers, $e->jsonSerialize());
        }

        return new Response(200, [
            'Content-Type' => 'application/json',
            'Cache-Control' => 'no-store',
            'Pragma' => 'no-cache'
        ], json_encode($responseData));
    }

    /**
     * @param ServerRequestInterface $request
     * @param array                  $requestData
     * @throws OAuthException
     */
    protected function verifyRequestData(ServerRequestInterface $request, array $requestData)
    {
        if (empty($requestData['grant_type'])) {
            throw new OAuthException('invalid_request', 'The request is missing the required parameter grant_type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        if (!($grantType = $this->grantTypeManager->getGrantType($requestData['grant_type']))) {
            throw new OAuthException('unsupported_grant_type',
                'The authorization grant type is not supported by the authorization server',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        $this->grantType = $grantType;

        $this->verifyClient($request, $requestData);

        $supportedGrantTypes = $this->client->getMetadata()->getGrantTypes() ?: ['authorization_code'];
        if (!in_array($requestData['grant_type'], $supportedGrantTypes)) {
            throw new OAuthException('unauthorized_client',
                'The authenticated client is not authorized to use this authorization grant type.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

    }

    /**
     * @param ServerRequestInterface $request
     * @param array                  $requestData
     * @throws OAuthException
     */
    protected function verifyClient(ServerRequestInterface $request, array $requestData)
    {
        // TODO authenticate if client is confidential
        // http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

        /**
         * require client authentication for confidential clients or for any
         * client that was issued client credentials (or with other
         * authentication requirements)
         */
        $this->client = $this->clientAuthenticationMethodManager->authenticate($request, $requestData);

        $this->getGrantType();
    }

    /**
     * @return null|GrantTypeInterface
     */
    public function getGrantType()
    {
        return $this->grantType;
    }

    /**
     * @return null|RegisteredClient
     */
    public function getClient(): ?RegisteredClient
    {
        return $this->client;
    }
}
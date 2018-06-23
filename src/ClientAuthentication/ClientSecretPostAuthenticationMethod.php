<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 16:59
 */

namespace OAuth2\ClientAuthentication;


use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ClientTypes\ConfidentialClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class ClientSecretPostAuthenticationMethod
 * @package OAuth2\ClientAuthentication
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
 * The authorization server MAY support including the
 * client credentials in the request-body using the following
 * parameters:
 *
 * client_id
 * REQUIRED.  The client identifier issued to the client during
 * the registration process described by Section 2.2.
 *
 * client_secret
 * REQUIRED.  The client secret.  The client MAY omit the
 * parameter if the client secret is an empty string.
 *
 *  Including the client credentials in the request-body using the two
 * parameters is NOT RECOMMENDED and SHOULD be limited to clients unable
 * to directly utilize the HTTP Basic authentication scheme (or other
 * password-based HTTP authentication schemes).  The parameters can only
 * be transmitted in the request-body and MUST NOT be included in the
 * request URI.
 */
class ClientSecretPostAuthenticationMethod implements ClientAuthenticationMethodInterface, PasswordAuthenticationInterface
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
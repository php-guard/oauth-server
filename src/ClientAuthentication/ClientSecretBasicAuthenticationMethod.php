<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 09/03/2018
 * Time: 16:58
 */

namespace OAuth2\ClientAuthentication;


use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ClientTypes\ConfidentialClient;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * Class ClientSecretBasicAuthenticationMethod
 * @package OAuth2\ClientAuthentication
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.3.1
 * Clients in possession of a client password MAY use the HTTP Basic
 * authentication scheme as defined in [RFC2617] to authenticate with
 * the authorization server.  The client identifier is encoded using the
 * "application/x-www-form-urlencoded" encoding algorithm per
 * Appendix B, and the encoded value is used as the username; the client
 * password is encoded using the same algorithm and used as the
 * password.  The authorization server MUST support the HTTP Basic
 * authentication scheme for authenticating clients that were issued a
 * client password.
 *
 * For example (with extra line breaks for display purposes only):
 *
 * Authorization: Basic czZCaGRSa3F0Mzo3RmpmcDBaQnIxS3REUmJuZlZkbUl3
 */
class ClientSecretBasicAuthenticationMethod implements ClientAuthenticationMethodInterface, PasswordAuthenticationInterface
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
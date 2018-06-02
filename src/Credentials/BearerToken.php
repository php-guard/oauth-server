<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 27/05/2018
 * Time: 17:40
 */

namespace OAuth2\Credentials;


/**
 * Class BearerToken
 * @package OAuth2\Credentials
 *
 * @see https://tools.ietf.org/html/rfc6750#section-1.2
 * A security token with the property that any party in possession of
 * the token (a "bearer") can use the token in any way that any other
 * party in possession of it can.  Using a bearer token does not
 * require a bearer to prove possession of cryptographic key material
 * (proof-of-possession).
 */
class BearerToken extends AccessToken
{
    public function __construct(string $token, array $scopes, string $clientIdentifier,
                                ?string $resourceOwnerIdentifier,
                                \DateTimeInterface $expiresAt, ?string $authorizationCode = null)
    {
        parent::__construct('bearer', $token, $scopes, $clientIdentifier, $resourceOwnerIdentifier, $expiresAt,
            $authorizationCode);
    }
}
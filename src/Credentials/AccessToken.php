<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:55
 */

namespace OAuth2\Credentials;


/**
 * Class AccessToken
 * @package OAuth2\Credentials
 */
class AccessToken extends Token implements AccessTokenInterface
{
    /**
     * @var string
     */
    protected $type;

    public function __construct(string $type, string $token, array $scopes, string $clientIdentifier,
                                ?string $resourceOwnerIdentifier, \DateTimeInterface $expiresAt,
                                ?string $authorizationCode = null)
    {
        parent::__construct($token, $scopes, $clientIdentifier, $resourceOwnerIdentifier, $expiresAt, $authorizationCode);
        $this->type = $type;
    }

    public function getType(): string
    {
        return $this->type;
    }
}
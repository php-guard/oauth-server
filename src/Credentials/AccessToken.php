<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:55
 */

namespace OAuth2\Credentials;


class AccessToken extends Token implements AccessTokenInterface
{
    /**
     * @var string
     */
    protected $type;
    /**
     * @var string|null
     */
    protected $authorizationCode;

    public function __construct(string $token, string $type, array $scopes, string $clientIdentifier,
                                ?string $resourceOwnerIdentifier, \DateTimeInterface $expiresAt, ?string $authorizationCode = null)
    {
        parent::__construct($token, $scopes, $clientIdentifier, $resourceOwnerIdentifier, $expiresAt);
        $this->type = $type;
        $this->authorizationCode = $authorizationCode;
    }

    public function getType(): string
    {
        return $this->type;
    }

    /**
     * @return string
     */
    public function getAuthorizationCode(): ?string
    {
        return $this->authorizationCode;
    }
}
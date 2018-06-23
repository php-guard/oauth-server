<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/03/2018
 * Time: 15:57
 */

namespace OAuth2\Credentials;


abstract class Token implements TokenInterface
{
    /**
     * @var string
     */
    protected $token;
    /**
     * @var string[]
     */
    protected $scopes;
    /**
     * @var string
     */
    protected $clientIdentifier;
    /**
     * @var string|null
     */
    protected $resourceOwnerIdentifier;
    /**
     * @var \DateTimeInterface
     */
    protected $expiresAt;
    /**
     * @var string|null
     */
    protected $authorizationCode;
    /**
     * @var string|null
     */
    protected $refreshToken;

    public function __construct(string $token, array $scopes, string $clientIdentifier, ?string $resourceOwnerIdentifier,
                                \DateTimeInterface $expiresAt, ?string $authorizationCode = null, ?string $refreshToken = null)
    {
        $this->token = $token;
        $this->scopes = $scopes;
        $this->clientIdentifier = $clientIdentifier;
        $this->resourceOwnerIdentifier = $resourceOwnerIdentifier;
        $this->expiresAt = $expiresAt;
        $this->authorizationCode = $authorizationCode;
        $this->refreshToken = $refreshToken;
    }

    /**
     * @return string
     */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * @return string[]
     */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /**
     * @return string
     */
    public function getClientIdentifier(): string
    {
        return $this->clientIdentifier;
    }

    /**
     * @return string|null
     */
    public function getResourceOwnerIdentifier(): ?string
    {
        return $this->resourceOwnerIdentifier;
    }

    /**
     * @return \DateTimeInterface
     */
    public function getExpiresAt(): \DateTimeInterface
    {
        return $this->expiresAt;
    }

    /**
     * @return string
     */
    public function getAuthorizationCode(): ?string
    {
        return $this->authorizationCode;
    }

}
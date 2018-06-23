<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 21:57
 */

namespace OAuth2\Credentials;

class AuthorizationCode implements AuthorizationCodeInterface
{
    /**
     * @var string
     */
    protected $code;
    /**
     * @var string[]
     */
    protected $scopes;
    /**
     * @var string
     */
    protected $clientIdentifier;
    /**
     * @var string
     */
    protected $resourceOwnerIdentifier;
    /**
     * @var string[]|null
     */
    protected $requestedScopes;
    /**
     * @var string|null
     */
    protected $redirectUri;
    /**
     * @var \DateTimeInterface
     */
    protected $expiresAt;

    public function __construct(string $code, array $scopes, string $clientIdentifier, string $resourceOwnerIdentifier,
                                \DateTimeInterface $expiresAt, ?array $requestedScopes = null, ?string $redirectUri = null)
    {
        $this->code = $code;
        $this->scopes = $scopes;
        $this->clientIdentifier = $clientIdentifier;
        $this->resourceOwnerIdentifier = $resourceOwnerIdentifier;
        $this->expiresAt = $expiresAt;
        $this->requestedScopes = $requestedScopes;
        $this->redirectUri = $redirectUri;
    }

    /**
     * @return string
     */
    public function getCode(): string
    {
        return $this->code;
    }

    /**
     * @return array
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
     * @return string
     */
    public function getResourceOwnerIdentifier(): string
    {
        return $this->resourceOwnerIdentifier;
    }

    public function getExpiresAt(): \DateTimeInterface
    {
        return $this->expiresAt;
    }

    /**
     * @return null|string[]
     */
    public function getRequestedScopes(): ?array
    {
        return $this->requestedScopes;
    }

    /**
     * @return null|string
     */
    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }
}
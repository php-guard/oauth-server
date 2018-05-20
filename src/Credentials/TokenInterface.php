<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 19/05/2018
 * Time: 16:16
 */

namespace OAuth2\Credentials;


interface TokenInterface
{

    /**
     * @return string
     */
    public function getToken(): string;

    /**
     * @return string[]
     */
    public function getScopes(): array;

    /**
     * @return string
     */
    public function getClientIdentifier();

    /**
     * @return string|null
     */
    public function getResourceOwnerIdentifier();

    /**
     * @return \DateTimeInterface
     */
    public function getExpiresAt(): \DateTimeInterface;

    /**
     * @return string|null
     */
    public function getAuthorizationCode(): ?string;
}
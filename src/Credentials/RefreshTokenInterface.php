<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 22:24
 */

namespace OAuth2\Credentials;


interface RefreshTokenInterface
{
    function getToken(): string;

    function getScopes(): array;

    function getClientIdentifier(): string;

    function getResourceOwnerIdentifier(): ?string;

    function getExpiresAt(): \DateTimeInterface;
}
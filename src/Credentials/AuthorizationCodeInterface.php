<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:27
 */

namespace OAuth2\Credentials;


interface AuthorizationCodeInterface
{
    function getCode(): string;

    function getScopes(): array;

    function getClientIdentifier(): string;

    function getResourceOwnerIdentifier(): string;

    function getExpiresAt(): \DateTimeInterface;

    function getRequestedScopes(): ?array;

    function getRedirectUri(): ?string;
}
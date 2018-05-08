<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 21:30
 */

namespace OAuth2\Roles;


use OAuth2\Roles\Clients\ClientMetadataInterface;

interface ClientInterface
{
//    function getIdentifier(): string;
//
//    function getPassword(): ?string;

    function hasCredentials(): bool;

//    function isHttpBasicAuthenticationSchemeSupported(): bool;

//    function isTLSSupported(): bool;

    function getMetadata(): ClientMetadataInterface;
}
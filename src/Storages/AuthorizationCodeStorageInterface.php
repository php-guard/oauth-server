<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/03/2018
 * Time: 21:17
 */

namespace OAuth2\Storages;


use OAuth2\Credentials\AuthorizationCodeInterface;

interface AuthorizationCodeStorageInterface
{
    function get(string $code): ?AuthorizationCodeInterface;

    function revoke(string $code): void;

    function generate(array $scopes, string $clientIdentifier, string $resourceOwnerIdentifier,
                    ?array $requestedScopes, ?string $redirectUri): AuthorizationCodeInterface;

//    function save(AuthorizationCodeInterface $authorizationCode);

    function hasExpired(AuthorizationCodeInterface $authorizationCode): bool;

    function getSize(): ?int;
}
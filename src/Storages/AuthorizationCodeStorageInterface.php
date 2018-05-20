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

    /**
     * @param array $scopes
     * @param string $clientIdentifier
     * @param string $resourceOwnerIdentifier
     * @param array|null $requestedScopes
     * @param null|string $redirectUri
     * @return AuthorizationCodeInterface
     *
     *
     */
    function generate(array $scopes, string $clientIdentifier, string $resourceOwnerIdentifier,
                      ?array $requestedScopes, ?string $redirectUri): AuthorizationCodeInterface;

//    function save(AuthorizationCodeInterface $authorizationCode);

    /**
     * @param AuthorizationCodeInterface $authorizationCode
     * @return bool
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
     * The authorization code MUST expire
     * shortly after it is issued to mitigate the risk of leaks.  A
     * maximum authorization code lifetime of 10 minutes is
     * RECOMMENDED.
     */
    function hasExpired(AuthorizationCodeInterface $authorizationCode): bool;

    /**
     * @return int|null
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.2
     * The authorization code string size is left undefined by this
     * specification.  The client should avoid making assumptions about code
     * value sizes.  The authorization server SHOULD document the size of
     * any value it issues.
     */
    function getSize(): ?int;
}
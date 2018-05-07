<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 21:28
 */

namespace OAuth2\Roles;


use OAuth2\Endpoints\AuthorizationEndpoint;
use Psr\Http\Message\ResponseInterface;

interface ResourceOwnerInterface
{
    function getIdentifier(): string;

    /**
     * null: No decision given yet
     * scope[]: Allow decision given for specific scopes
     * Empty array: Deny decision given
     *
     * @param ClientInterface $client
     * @param array $scopes
     * @return array|null
     */
    function hasGivenConsent(ClientInterface $client, array $scopes): ?array;

    function obtainConsent(AuthorizationEndpoint $authorizationEndpoint, array $requestData): ResponseInterface;

    function isAuthenticated(): bool;

    function authenticate(): ResponseInterface;
}
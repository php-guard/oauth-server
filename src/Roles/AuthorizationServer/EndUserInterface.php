<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 11/01/2018
 * Time: 14:21
 */

namespace OAuth2\Roles\AuthorizationServer;

use OAuth2\Endpoints\Authorization\AuthorizationRequest;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ResourceOwnerInterface;
use Psr\Http\Message\ResponseInterface;



interface EndUserInterface
{
    public function getAuthenticatedResourceOwner(): ?ResourceOwnerInterface;

    public function authenticateResourceOwner(): ResponseInterface;

    /**
     * null: No decision given yet
     * scope[]: Allow decision given for specific scopes
     * Empty array: Deny decision given
     *
     * @param ClientInterface $client
     * @param array $scopes
     * @return array|null
     */
    public function hasGivenConsent(ClientInterface $client, array $scopes): ?array;

    public function obtainConsent(AuthorizationRequest $authorizationRequest): ResponseInterface;
}
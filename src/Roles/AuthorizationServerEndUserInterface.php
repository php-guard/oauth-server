<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 11/01/2018
 * Time: 14:21
 */

namespace OAuth2\Roles;

use OAuth2\Endpoints\AuthorizationRequest;
use Psr\Http\Message\ResponseInterface;



interface AuthorizationServerEndUserInterface
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
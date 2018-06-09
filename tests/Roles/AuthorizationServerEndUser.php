<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 18:24
 */

namespace OAuth2\Tests\Roles;


use GuzzleHttp\Psr7\Response;
use OAuth2\Endpoints\AuthorizationRequest;

use OAuth2\Extensions\OpenID\Roles\AuthorizationServer\EndUserInterface;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ResourceOwnerInterface;
use Psr\Http\Message\ResponseInterface;

class AuthorizationServerEndUser implements EndUserInterface
{
    private $resourceOwner;

    public function __construct()
    {
        $this->resourceOwner = new ResourceOwner();
    }

    public function getAuthenticatedResourceOwner(): ?ResourceOwnerInterface
    {
        return $this->resourceOwner;
    }

    public function isResourceOwnerAuthenticated(bool $alwaysAuthenticate = false): bool
    {
        return true;
    }

    public function authenticateResourceOwner(bool $accountSelectionRequired = false, ?string $loginHint = null): ResponseInterface
    {
        return new Response();
    }

    /**
     * null: No decision given yet
     * false: Deny decision given
     * true: Allow decision given
     * scope[]: Allow decision given for specific scopes
     * An empty array is equivalent to false (deny decision)
     *
     * @param ClientInterface $client
     * @param array $scopes
     * @param bool|null $alwaysPromptConsent
     * @return array
     */
    public function hasGivenConsent(ClientInterface $client, array $scopes, ?bool $alwaysPromptConsent = false): array
    {
        return $scopes;
    }

    public function obtainConsent(AuthorizationRequest $authorizationRequest): ResponseInterface
    {
        return new Response();
    }

    public function getLastTimeActivelyAuthenticated(): ?\DateTime
    {
        return null;
    }

    public function isInteractionRequiredForConsent(AuthorizationRequest $authorizationRequest): bool
    {
        return !$authorizationRequest->getClient()->hasCredentials();
    }

    public function getAuthenticationContextClassReference()
    {
        return null;
    }

    public function getAuthenticationMethodsReferences(): ?array
    {
        return null;
    }

    public function getClaims(array $scopes): array
    {
        if (in_array('email', $scopes)) {
            return ['email' => 'phpunit@oauth-server.com'];
        }
        return [];
    }
}
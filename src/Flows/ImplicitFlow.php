<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\GrantTypes\AbstractGrantType;


class ImplicitFlow extends AbstractGrantType implements FlowInterface
{
    public function getResponseTypes(): array
    {
        return ['token'];
    }

    public function verifyAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData)
    {
    }

    public function handleAuthorizationRequest(AuthorizationEndpoint $authorizationEndpoint, array $requestData): array
    {
        $data = $this->issueAccessToken(
            $authorizationEndpoint->getScopes(),
            $authorizationEndpoint->getClient()->getIdentifier(),
            $authorizationEndpoint->getResourceOwner()->getIdentifier()
        );

        if (!$this->arrayEqual($authorizationEndpoint->getScopes(), $requestData['scope'] ?? null)) {
            $data['scope'] = implode(' ', $authorizationEndpoint->getScopes());
        }

        return $data;
    }

    public function getDefaultResponseMode(): string
    {
        return 'fragment';
    }

    public function getUnsupportedResponseModes(): array
    {
        return ['query'];
    }

    public function getGrantTypes(): array
    {
        return [];
    }

    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        throw new \BadMethodCallException();
    }

    private function arrayEqual($a, $b)
    {
        return (
            is_array($a)
            && is_array($b)
            && count($a) == count($b)
            && array_diff($a, $b) === array_diff($b, $a)
        );
    }
}
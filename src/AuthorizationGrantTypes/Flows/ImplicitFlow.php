<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;


/**
 * Class ImplicitFlow
 * @package OAuth2\AuthorizationGrantTypes\Flows
 *
 * @see https://tools.ietf.org/html/rfc6749#section-1.3.2
 * The implicit grant is a simplified authorization code flow optimized
 * for clients implemented in a browser using a scripting language such
 * as JavaScript.  In the implicit flow, instead of issuing the client
 * an authorization code, the client is issued an access token directly
 * (as the result of the resource owner authorization).  The grant type
 * is implicit, as no intermediate credentials (such as an authorization
 * code) are issued (and later used to obtain an access token).
 *
 * When issuing an access token during the implicit grant flow, the
 * authorization server does not authenticate the client.  In some
 * cases, the client identity can be verified via the redirection URI
 * used to deliver the access token to the client.  The access token may
 * be exposed to the resource owner or other applications with access to
 * the resource owner's user-agent.
 *
 * Implicit grants improve the responsiveness and efficiency of some
 * clients (such as a client implemented as an in-browser application),
 * since it reduces the number of round trips required to obtain an
 * access token.  However, this convenience should be weighed against
 * the security implications of using implicit grants, such as those
 * described in Sections 10.3 and 10.16, especially when the
 * authorization code grant type is available.
 *
 */
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

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.3
         * The authorization and token endpoints allow the client to specify the
         * scope of the access request using the "scope" request parameter.  In
         * turn, the authorization server uses the "scope" response parameter to
         * inform the client of the scope of the access token issued.
         */
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
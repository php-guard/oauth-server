<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\Endpoints\Authorization\AuthorizationRequest;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\AuthorizationGrantTypes\AbstractGrantType;
use OAuth2\Helper;


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
 * @see https://tools.ietf.org/html/rfc6749#section-4.2
 *  The implicit grant type is used to obtain access tokens (it does not
 * support the issuance of refresh tokens) and is optimized for public
 * clients known to operate a particular redirection URI.  These clients
 * are typically implemented in a browser using a scripting language
 * such as JavaScript.
 *
 * Since this is a redirection-based flow, the client must be capable of
 * interacting with the resource owner's user-agent (typically a web
 * browser) and capable of receiving incoming requests (via redirection)
 * from the authorization server.
 *
 * Unlike the authorization code grant type, in which the client makes
 * separate requests for authorization and for an access token, the
 * client receives the access token as the result of the authorization
 * request.
 *
 * The implicit grant type does not include client authentication, and
 * relies on the presence of the resource owner and the registration of
 * the redirection URI.  Because the access token is encoded into the
 * redirection URI, it may be exposed to the resource owner and other
 * applications residing on the same device.
 *
 * See Sections 1.3.2 and 9 for background on using the implicit grant.
 * See Sections 10.3 and 10.16 for important security considerations
 * when using the implicit grant.
 */
class ImplicitFlow extends AbstractGrantType implements FlowInterface
{
    /**
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.2.1
     * response_type
     * REQUIRED.  Value MUST be set to "token".
     */
    public function getResponseTypes(): array
    {
        return ['token'];
    }

    /**
     * @param AuthorizationRequest $authorizationRequest
     * @return array
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.2.2
     * If the resource owner grants the access request, the authorization
     * server issues an access token and delivers it to the client by adding
     * the following parameters to the fragment component of the redirection
     * URI using the "application/x-www-form-urlencoded" format, per
     * Appendix B:
     *
     * access_token
     * REQUIRED.  The access token issued by the authorization server.
     *
     * token_type
     * REQUIRED.  The type of the token issued as described in
     * Section 7.1.  Value is case insensitive.
     *
     * expires_in
     * RECOMMENDED.  The lifetime in seconds of the access token.  For
     * example, the value "3600" denotes that the access token will
     * expire in one hour from the time the response was generated.
     * If omitted, the authorization server SHOULD provide the
     * expiration time via other means or document the default value.
     *
     * scope
     * OPTIONAL, if identical to the scope requested by the client;
     * otherwise, REQUIRED.  The scope of the access token as
     * described by Section 3.3.
     *
     * state
     * REQUIRED if the "state" parameter was present in the client
     * authorization request.  The exact value received from the
     * client.
     *
     * The authorization server MUST NOT issue a refresh token.
     *
     * For example, the authorization server redirects the user-agent by
     * sending the following HTTP response (with extra line breaks for
     * display purposes only):
     *
     * HTTP/1.1 302 Found
     * Location: http://example.com/cb#access_token=2YotnFZFEjr1zCsicMWpAA
     * &state=xyz&token_type=example&expires_in=3600
     *
     * Developers should note that some user-agents do not support the
     * inclusion of a fragment component in the HTTP "Location" response
     * header field.  Such clients will require using other methods for
     * redirecting the client than a 3xx redirection response -- for
     * example, returning an HTML page that includes a 'continue' button
     * with an action linked to the redirection URI.
     *
     * The client MUST ignore unrecognized response parameters.  The access
     * token string size is left undefined by this specification.  The
     * client should avoid making assumptions about value sizes.  The
     * authorization server SHOULD document the size of any value it issues.
     */
    public function handleAuthorizationRequest(AuthorizationRequest $authorizationRequest): array
    {
        $data = $this->issueAccessToken(
            $authorizationRequest->getScopes(),
            $authorizationRequest->getClient()->getIdentifier(),
            $authorizationRequest->getResourceOwner()->getIdentifier()
        );

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-3.3
         * The authorization and token endpoints allow the client to specify the
         * scope of the access request using the "scope" request parameter.  In
         * turn, the authorization server uses the "scope" response parameter to
         * inform the client of the scope of the access token issued.
         */
        if (!Helper::array_equals($authorizationRequest->getScopes(), $authorizationRequest->getRequestedScopes())) {
            $data['scope'] = implode(' ', $authorizationRequest->getScopes());
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

    public function isRegistrationOfRedirectUriRequired(): bool
    {
        return true;
    }

    public function getGrantTypes(): array
    {
        return [];
    }

    public function handleAccessTokenRequest(TokenEndpoint $tokenEndpoint, array $requestData): array
    {
        throw new \BadMethodCallException();
    }
}
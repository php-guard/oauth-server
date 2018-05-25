<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 12/03/2018
 * Time: 21:35
 */

namespace OAuth2\Extensions\OpenID\Roles;


use OAuth2\Endpoints\AuthorizationRequest;

use OAuth2\Roles\ClientInterface;
use Psr\Http\Message\ResponseInterface;

interface ResourceOwnerInterface extends \OAuth2\Roles\ResourceOwnerInterface
{
    public function getLastTimeActivelyAuthenticated(): ?\DateTime;

    /**
     * You should handle theses values for the prompt parameter : select_account
     * @param bool $accountSelectionRequired
     * @param null|string $loginHint
     * @return ResponseInterface
     */
    public function authenticate(bool $accountSelectionRequired = false, ?string $loginHint = null): ResponseInterface;

    /**
     * If prompt value is login, server should re-authenticate the user. This means that this predicate should return
     * false, then authenticate() will be called and if login is successful, server handle again the authorization request
     * but returning true in isAuthenticatedMethod. Use a CSRF token like to handle this.
     *
     * @param bool $alwaysAuthenticate
     * @return bool
     */
    public function isAuthenticated(bool $alwaysAuthenticate = false): bool;

    public function hasGivenConsent(ClientInterface $client, array $scopes, ?bool $alwaysPromptConsent = false): ?array;

    public function obtainConsent(AuthorizationRequest $authorizationRequest): ResponseInterface;

    public function isInteractionRequiredForConsent(AuthorizationRequest $authorizationRequest): bool;

    public function getClaims(array $scopes): array;
    /**
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     *
     * String specifying an Authentication Context Class Reference value that identifies the Authentication Context Class
     * that the authentication performed satisfied.
     * The value "0" indicates the End-User authentication did not meet the requirements of ISO/IEC 29115 [ISO29115] level 1.
     * Authentication using a long-lived browser cookie, for instance, is one example where the use of "level 0" is appropriate.
     * Authentications with level 0 SHOULD NOT be used to authorize access to any resource of any monetary value.
     * (This corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level 0.)
     * An absolute URI or an RFC 6711 [RFC6711] registered name SHOULD be used as the acr value;
     * registered names MUST NOT be used with a different meaning than that which is registered.
     * Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific.
     * The acr value is a case sensitive string.
     *
     * @return mixed
     */
    public function getAuthenticationContextClassReference();

    /**
     * @see http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     *
     * JSON array of strings that are identifiers for authentication methods used in the authentication.
     * For instance, values might indicate that both password and OTP authentication methods were used.
     * The definition of particular values to be used in the amr Claim is beyond the scope of this specification.
     * Parties using this claim will need to agree upon the meanings of the values used, which may be context-specific.
     *
     * @return string[]|null
     */
    public function getAuthenticationMethodsReferences(): ?array;
}
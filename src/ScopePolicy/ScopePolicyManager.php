<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 15/01/2018
 * Time: 09:54
 */

namespace OAuth2\ScopePolicy;


use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;
use OAuth2\ScopePolicy\Policies\ScopePolicyInterface;


/**
 * Class ScopePolicyManager
 * @package OAuth2\ScopePolicy
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.3
 * The authorization and token endpoints allow the client to specify the
 * scope of the access request using the "scope" request parameter.  In
 * turn, the authorization server uses the "scope" response parameter to
 * inform the client of the scope of the access token issued.
 *
 * The value of the scope parameter is expressed as a list of space-
 * delimited, case-sensitive strings.  The strings are defined by the
 * authorization server.  If the value contains multiple space-delimited
 * strings, their order does not matter, and each string adds an
 * additional access range to the requested scope.
 *
 * scope       = scope-token *( SP scope-token )
 * scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
 *
 * The authorization server MAY fully or partially ignore the scope
 * requested by the client, based on the authorization server policy or
 * the resource owner's instructions.  If the issued access token scope
 * is different from the one requested by the client, the authorization
 * server MUST include the "scope" response parameter to inform the
 * client of the actual scope granted.
 *
 * If the client omits the scope parameter when requesting
 * authorization, the authorization server MUST either process the
 * request using a pre-defined default value or fail the request
 * indicating an invalid scope.  The authorization server SHOULD
 * document its scope requirements and default value (if defined).
 */
class ScopePolicyManager
{
    /**
     * @var ScopePolicyInterface
     */
    private $scopePolicy;

    /**
     * ScopePolicyManager constructor.
     * @param ScopePolicyInterface $scopePolicy
     */
    public function __construct(ScopePolicyInterface $scopePolicy)
    {
        $this->scopePolicy = $scopePolicy;
    }

    /**
     * @see https://tools.ietf.org/html/rfc6749#section-3.3
     * The value of the scope parameter is expressed as a list of space-
     * delimited, case-sensitive strings.  The strings are defined by the
     * authorization server.  If the value contains multiple space-delimited
     * strings, their order does not matter, and each string adds an
     * additional access range to the requested scope.
     *
     * scope       = scope-token *( SP scope-token )
     * scope-token = 1*( %x21 / %x23-5B / %x5D-7E )
     *
     * @param null|string $scopes
     * @return array|null
     */
    public function scopeStringToArray(?string $scopes): ?array {
        return empty(trim($scopes)) ? null : array_filter(explode(' ', $scopes));
    }

    /**
     * @param ClientInterface $client
     * @param array|null $requestedScopes
     * @return array|null
     * @throws OAuthException
     */
    public function getScopes(ClientInterface $client, ?array $requestedScopes): array
    {
        $scopes = $this->scopePolicy->getScopes($client, $requestedScopes);

        if (empty($scopes)) {
            throw new OAuthException('invalid_scope',
                'The request scope is unknown.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        $supportedScopes = $client->getMetadata()->getScopes();
        if (!empty($supportedScopes)) {
            if (!empty(array_diff($scopes, $supportedScopes))) {
                throw new OAuthException('invalid_scope',
                    'The request scope is invalid. Supported scopes : ' . implode(', ', $supportedScopes),
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }
        }

        return $scopes;
    }

    /**
     * @param ClientInterface $client
     * @param array $scopes
     * @throws OAuthException
     * @deprecated
     */
    public function verifyScopes(ClientInterface $client, array $scopes): void
    {
        if (empty($scopes)) {
            throw new OAuthException('invalid_scope',
                'The request scope is unknown.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        $supportedScopes = $client->getMetadata()->getScopes();
        if ($client instanceof RegisteredClient && !empty($supportedScopes)) {
            if (!empty(array_diff($scopes, $supportedScopes))) {
                throw new OAuthException('invalid_scope',
                    'The request scope is invalid. Supported scopes : ' . implode(', ', $supportedScopes),
                    'https://tools.ietf.org/html/rfc6749#section-4.1');
            }
        }
    }
}
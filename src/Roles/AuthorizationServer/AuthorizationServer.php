<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/03/2018
 * Time: 15:55
 */

namespace OAuth2\Roles\AuthorizationServer;

use OAuth2\Endpoints\AuthorizationEndpoint;
use OAuth2\Endpoints\EndpointInterface;
use OAuth2\Endpoints\TokenEndpoint;
use OAuth2\Endpoints\TokenRevocationEndpoint;
use OAuth2\Roles\AuthorizationServerInterface;


class AuthorizationServer implements AuthorizationServerInterface
{
    protected $authorizationEndpoint;
    protected $tokenEndpoint;
    protected $tokenRevocationEndpoint;

    public function __construct(AuthorizationEndpoint $authorizationEndpoint,
                                TokenEndpoint $tokenEndpoint,
                                TokenRevocationEndpoint $tokenRevocationEndpoint)
    {

        $this->authorizationEndpoint = $authorizationEndpoint;
        $this->tokenEndpoint = $tokenEndpoint;
        $this->tokenRevocationEndpoint = $tokenRevocationEndpoint;
    }

    /**
     * @return AuthorizationEndpoint
     */
    public function getAuthorizationEndpoint(): EndpointInterface
    {
        return $this->authorizationEndpoint;
    }

    /**
     * @return TokenEndpoint
     */
    public function getTokenEndpoint(): EndpointInterface
    {
        return $this->tokenEndpoint;
    }

    /**
     * @return TokenRevocationEndpoint
     */
    public function getTokenRevocationEndpoint(): EndpointInterface
    {
        return $this->tokenRevocationEndpoint;
    }

    /**
     * @return bool
     *
     * @see https://tools.ietf.org/html/rfc6749#section-3.1.2.1
     *
     *  Endpoint Request Confidentiality
     *
     *     The redirection endpoint SHOULD require the use of TLS as described
     * in Section 1.6 when the requested response type is "code" or "token",
     * or when the redirection request will result in the transmission of
     * sensitive credentials over an open network.  This specification does
     * not mandate the use of TLS because at the time of this writing,
     * requiring clients to deploy TLS is a significant hurdle for many
     * client developers.  If TLS is not available, the authorization server
     * SHOULD warn the resource owner about the insecure endpoint prior to
     * redirection (e.g., display a message during the authorization
     * request).
     *
     * Lack of transport-layer security can have a severe impact on the
     * security of the client and the protected resources it is authorized
     * to access.  The use of transport-layer security is particularly
     * critical when the authorization process is used as a form of
     * delegated end-user authentication by the client (e.g., third-party
     * sign-in service).
     * @deprecated
     */
    public function isSecure()
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || $_SERVER['SERVER_PORT'] == 443;
    }
}
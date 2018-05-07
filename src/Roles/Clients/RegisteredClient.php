<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:36
 */

namespace OAuth2\Roles\Clients;

use OAuth2\Roles\ClientInterface;


/**
 * Class RegisteredClient
 * @package        OAuth2\Roles\Clients
 *
 * @see            https://tools.ietf.org/html/rfc6749#section-2
 *
 * Client Registration
 *
 *     Before initiating the protocol, the client registers with the
 * authorization server.  The means through which the client registers
 * with the authorization server are beyond the scope of this
 * specification but typically involve end-user interaction with an HTML
 * registration form.
 *
 * Client registration does not require a direct interaction between the
 * client and the authorization server.  When supported by the
 * authorization server, registration can rely on other means for
 * establishing trust and obtaining the required client properties
 * (e.g., redirection URI, client type).  For example, registration can
 * be accomplished using a self-issued or third-party-issued assertion,
 * or by the authorization server performing client discovery using a
 * trusted channel.
 *
 * When registering a client, the client developer SHALL:
 * o  specify the client type as described in Section 2.1,
 * o  provide its client redirection URIs as described in Section 3.1.2,
 * and
 * o  include any other information required by the authorization server
 * (e.g., application name, website, description, logo image, the
 * acceptance of legal terms).
 *
 * @implementation If registration require additional information,
 * you should override this class and all of his children to add your own properties
 */
abstract class RegisteredClient implements ClientInterface
{
    /**
     * @var string
     *
     * @see https://tools.ietf.org/html/rfc6749#section-2.2
     *
     * Client Identifier
     *
     *     The authorization server issues the registered client a client
     * identifier -- a unique string representing the registration
     * information provided by the client.  The client identifier is not a
     * secret; it is exposed to the resource owner and MUST NOT be used
     * alone for client authentication.  The client identifier is unique to
     * the authorization server.
     *
     * The client identifier string size is left undefined by this
     * specification.  The client should avoid making assumptions about the
     * identifier size.  The authorization server SHOULD document the size
     * of any identifier it issues.
     */
    protected $identifier;

    /**
     * @var bool
     */
    protected $tlsSupported = true;
    /**
     * @var bool
     */
    protected $httpBasicAuthenticationSchemeSupported = true;
    /**
     * @var ClientMetadata
     */
    protected $metadata;

    public function __construct(string $identifier, ClientMetadataInterface $metadata)
    {
        $this->identifier = $identifier;
        $this->metadata = $metadata;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function isTlsSupported(): bool
    {
        return $this->tlsSupported;
    }

    /**
     * @param bool $tlsSupported
     */
    public function setTlsSupported(bool $tlsSupported)
    {
        $this->tlsSupported = $tlsSupported;
    }

    /**
     * @return bool
     */
    public function isHttpBasicAuthenticationSchemeSupported(): bool
    {
        return $this->httpBasicAuthenticationSchemeSupported;
    }

    /**
     * @param bool $httpBasicAuthenticationSchemeSupported
     */
    public function setHttpBasicAuthenticationSchemeSupported(bool $httpBasicAuthenticationSchemeSupported)
    {
        $this->httpBasicAuthenticationSchemeSupported = $httpBasicAuthenticationSchemeSupported;
    }

    /**
     * @return ClientMetadataInterface
     */
    public function getMetadata(): ClientMetadataInterface
    {
        return $this->metadata;
    }

}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:36
 */

namespace OAuth2\Roles\ClientTypes;


/**
 * Class RegisteredClient
 * @package        OAuth2\Roles\Clients
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2
 * Before initiating the protocol, the client registers with the
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
 */
abstract class RegisteredClient implements RegisteredClientInterface
{
    /**
     * @var string
     */
    protected $identifier;

    /**
     * @var ClientMetadataInterface
     */
    protected $metadata;

    /**
     * @var bool
     */
    protected $tlsSupported = true;
    /**
     * @var bool
     */
    protected $httpBasicAuthenticationSchemeSupported = true;

    public function __construct(string $identifier, ClientMetadataInterface $metadata)
    {
        $this->identifier = $identifier;
        $this->metadata = $metadata;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    /**
     * @return ClientMetadataInterface
     */
    public function getMetadata(): ClientMetadataInterface
    {
        return $this->metadata;
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

}
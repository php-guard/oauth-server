<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 07/01/2018
 * Time: 13:42
 */

namespace OAuth2\Roles\ClientTypes;

use OAuth2\Roles\ClientInterface;

/**
 * Class UnregisteredClient
 * @package OAuth2\roles\clients
 *
 * @see https://tools.ietf.org/html/rfc6749#section-2.4
 * This specification does not exclude the use of unregistered clients.
 * However, the use of such clients is beyond the scope of this
 * specification and requires additional security analysis and review of
 * its interoperability impact.
 *
 * http://iiw.idcommons.net/images/2/27/UnregisteredClientExtension.pdf
 */
abstract class UnregisteredClient implements ClientInterface
{
    /**
     * @var ClientMetadataInterface
     */
    private $clientMetadata;

    public function __construct(ClientMetadataInterface $clientMetadata)
    {
        $this->clientMetadata = $clientMetadata;
    }

    /**
     * @return ClientMetadataInterface
     */
    public function getMetadata(): ClientMetadataInterface
    {
        return $this->clientMetadata;
    }
}
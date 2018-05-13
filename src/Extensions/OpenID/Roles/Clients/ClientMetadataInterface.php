<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 15/03/2018
 * Time: 23:12
 */

namespace OAuth2\Extensions\OpenID\Roles\Clients;

/**
 * Interface ClientMetadataInterface
 * @package OAuth2\Extensions\OpenID\Roles\Clients
 * rfc http://openid.net/specs/openid-connect-registration-1_0.html
 */
interface ClientMetadataInterface extends \OAuth2\Roles\ClientTypes\ClientMetadataInterface
{
    /**
     * @return null|string
     */
    function getApplicationType(): ?string;
    /**
     * @return null|string
     */
    function getSectorIdentifierUri(): ?string;

    /**
     * @return null|string
     */
    function getSubjectType(): ?string;

    /**
     * @return null|string
     */
    function getIdTokenSignedResponseAlg(): ?string;

    /**
     * @return null|string
     */
    function getIdTokenEncryptedResponseAlg(): ?string;
    /**
     * @return null|string
     */
    function getIdTokenEncryptedResponseEnc(): ?string;
    /**
     * @return null|string
     */
    function getUserinfoSignedResponseAlg(): ?string;
    /**
     * @return null|string
     */
    function getUserinfoEncryptedResponseAlg(): ?string;
    /**
     * @return null|string
     */
    function getUserinfoEncryptedResponseEnc(): ?string;

    /**
     * @return null|string
     */
    function getRequestObjectSigningAlg(): ?string;

    /**
     * @return null|string
     */
    function getRequestObjectEncryptionAlg(): ?string;

    /**
     * @return null|string
     */
    function getRequestObjectEncryptionEnc(): ?string;

    /**
     * @return null|string
     */
    function getTokenEndpointAuthSigningAlg(): ?string;

    /**
     * @return int|null
     */
    function getDefaultMaxAge(): ?int;
    /**
     * @return bool|null
     */
    function getRequireAuthTime(): ?bool;

    /**
     * @return null|string[]
     */
    function getDefaultAcrValues(): ?array;

    /**
     * @return null|string
     */
    function getInitiateLoginUri(): ?string;

    /**
     * @return null|string[]
     */
    function getRequestUris(): ?array;
}
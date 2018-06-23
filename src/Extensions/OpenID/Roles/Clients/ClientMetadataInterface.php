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
public function getApplicationType(): ?string;
    /**
     * @return null|string
     */
public function getSectorIdentifierUri(): ?string;

    /**
     * @return null|string
     */
public function getSubjectType(): ?string;

    /**
     * @return null|string
     */
public function getIdTokenSignedResponseAlg(): ?string;

    /**
     * @return null|string
     */
public function getIdTokenEncryptedResponseAlg(): ?string;
    /**
     * @return null|string
     */
public function getIdTokenEncryptedResponseEnc(): ?string;
    /**
     * @return null|string
     */
public function getUserinfoSignedResponseAlg(): ?string;
    /**
     * @return null|string
     */
public function getUserinfoEncryptedResponseAlg(): ?string;
    /**
     * @return null|string
     */
public function getUserinfoEncryptedResponseEnc(): ?string;

    /**
     * @return null|string
     */
public function getRequestObjectSigningAlg(): ?string;

    /**
     * @return null|string
     */
public function getRequestObjectEncryptionAlg(): ?string;

    /**
     * @return null|string
     */
public function getRequestObjectEncryptionEnc(): ?string;

    /**
     * @return null|string
     */
public function getTokenEndpointAuthSigningAlg(): ?string;

    /**
     * @return int|null
     */
public function getDefaultMaxAge(): ?int;
    /**
     * @return bool|null
     */
public function getRequireAuthTime(): ?bool;

    /**
     * @return null|string[]
     */
public function getDefaultAcrValues(): ?array;

    /**
     * @return null|string
     */
public function getInitiateLoginUri(): ?string;

    /**
     * @return null|string[]
     */
public function getRequestUris(): ?array;
}
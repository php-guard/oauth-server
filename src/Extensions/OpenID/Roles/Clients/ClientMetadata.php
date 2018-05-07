<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 15/03/2018
 * Time: 22:56
 */

namespace OAuth2\Extensions\OpenID\Roles\Clients;


class ClientMetadata extends \OAuth2\Roles\Clients\ClientMetadata implements ClientMetadataInterface
{
    /**
     * @var string|null
     */
    protected $applicationType;

    /**
     * @var string|null
     */
    protected $sectorIdentifierUri;

    /**
     * @var string|null
     */
    protected $subjectType;

    /**
     * @var string|null
     */
    protected $idTokenSignedResponseAlg;

    /**
     * @var string|null
     */
    protected $idTokenEncryptedResponseAlg;

    /**
     * @var string|null
     */
    protected $idTokenEncryptedResponseEnc;

    /**
     * @var string|null
     */
    protected $userinfoSignedResponseAlg;

    /**
     * @var string|null
     */
    protected $userinfoEncryptedResponseAlg;

    /**
     * @var string|null
     */
    protected $userinfoEncryptedResponseEnc;

    /**
     * @var string|null
     */
    protected $requestObjectSigningAlg;

    /**
     * @var string|null
     */
    protected $requestObjectEncryptionAlg;

    /**
     * @var string|null
     */
    protected $requestObjectEncryptionEnc;

    /**
     * @var string|null
     */
    protected $tokenEndpointAuthSigningAlg;

    /**
     * @var int|null
     */
    protected $defaultMaxAge;

    /**
     * @var bool|null
     */
    protected $requireAuthTime;

    /**
     * @var string[]|null
     */
    protected $defaultAcrValues;

    /**
     * @var string|null
     */
    protected $initiateLoginUri;

    /**
     * @var string[]|null
     */
    protected $requestUris;

    /**
     * @return null|string
     */
    public function getApplicationType(): ?string
    {
        return $this->applicationType;
    }

    /**
     * @param null|string $applicationType
     */
    public function setApplicationType(?string $applicationType): void
    {
        $this->applicationType = $applicationType;
    }

    /**
     * @return null|string
     */
    public function getSectorIdentifierUri(): ?string
    {
        return $this->sectorIdentifierUri;
    }

    /**
     * @param null|string $sectorIdentifierUri
     */
    public function setSectorIdentifierUri(?string $sectorIdentifierUri): void
    {
        $this->sectorIdentifierUri = $sectorIdentifierUri;
    }

    /**
     * @return null|string
     */
    public function getSubjectType(): ?string
    {
        return $this->subjectType;
    }

    /**
     * @param null|string $subjectType
     */
    public function setSubjectType(?string $subjectType): void
    {
        $this->subjectType = $subjectType;
    }

    /**
     * @return null|string
     */
    public function getIdTokenSignedResponseAlg(): ?string
    {
        return $this->idTokenSignedResponseAlg;
    }

    /**
     * @param null|string $idTokenSignedResponseAlg
     */
    public function setIdTokenSignedResponseAlg(?string $idTokenSignedResponseAlg): void
    {
        $this->idTokenSignedResponseAlg = $idTokenSignedResponseAlg;
    }

    /**
     * @return null|string
     */
    public function getIdTokenEncryptedResponseAlg(): ?string
    {
        return $this->idTokenEncryptedResponseAlg;
    }

    /**
     * @param null|string $idTokenEncryptedResponseAlg
     */
    public function setIdTokenEncryptedResponseAlg(?string $idTokenEncryptedResponseAlg): void
    {
        $this->idTokenEncryptedResponseAlg = $idTokenEncryptedResponseAlg;
    }

    /**
     * @return null|string
     */
    public function getIdTokenEncryptedResponseEnc(): ?string
    {
        return $this->idTokenEncryptedResponseEnc;
    }

    /**
     * @param null|string $idTokenEncryptedResponseEnc
     */
    public function setIdTokenEncryptedResponseEnc(?string $idTokenEncryptedResponseEnc): void
    {
        $this->idTokenEncryptedResponseEnc = $idTokenEncryptedResponseEnc;
    }

    /**
     * @return null|string
     */
    public function getUserinfoSignedResponseAlg(): ?string
    {
        return $this->userinfoSignedResponseAlg;
    }

    /**
     * @param null|string $userinfoSignedResponseAlg
     */
    public function setUserinfoSignedResponseAlg(?string $userinfoSignedResponseAlg): void
    {
        $this->userinfoSignedResponseAlg = $userinfoSignedResponseAlg;
    }

    /**
     * @return null|string
     */
    public function getUserinfoEncryptedResponseAlg(): ?string
    {
        return $this->userinfoEncryptedResponseAlg;
    }

    /**
     * @param null|string $userinfoEncryptedResponseAlg
     */
    public function setUserinfoEncryptedResponseAlg(?string $userinfoEncryptedResponseAlg): void
    {
        $this->userinfoEncryptedResponseAlg = $userinfoEncryptedResponseAlg;
    }

    /**
     * @return null|string
     */
    public function getUserinfoEncryptedResponseEnc(): ?string
    {
        return $this->userinfoEncryptedResponseEnc;
    }

    /**
     * @param null|string $userinfoEncryptedResponseEnc
     */
    public function setUserinfoEncryptedResponseEnc(?string $userinfoEncryptedResponseEnc): void
    {
        $this->userinfoEncryptedResponseEnc = $userinfoEncryptedResponseEnc;
    }

    /**
     * @return null|string
     */
    public function getRequestObjectSigningAlg(): ?string
    {
        return $this->requestObjectSigningAlg;
    }

    /**
     * @param null|string $requestObjectSigningAlg
     */
    public function setRequestObjectSigningAlg(?string $requestObjectSigningAlg): void
    {
        $this->requestObjectSigningAlg = $requestObjectSigningAlg;
    }

    /**
     * @return null|string
     */
    public function getRequestObjectEncryptionAlg(): ?string
    {
        return $this->requestObjectEncryptionAlg;
    }

    /**
     * @param null|string $requestObjectEncryptionAlg
     */
    public function setRequestObjectEncryptionAlg(?string $requestObjectEncryptionAlg): void
    {
        $this->requestObjectEncryptionAlg = $requestObjectEncryptionAlg;
    }

    /**
     * @return null|string
     */
    public function getRequestObjectEncryptionEnc(): ?string
    {
        return $this->requestObjectEncryptionEnc;
    }

    /**
     * @param null|string $requestObjectEncryptionEnc
     */
    public function setRequestObjectEncryptionEnc(?string $requestObjectEncryptionEnc): void
    {
        $this->requestObjectEncryptionEnc = $requestObjectEncryptionEnc;
    }

    /**
     * @return null|string
     */
    public function getTokenEndpointAuthSigningAlg(): ?string
    {
        return $this->tokenEndpointAuthSigningAlg;
    }

    /**
     * @param null|string $tokenEndpointAuthSigningAlg
     */
    public function setTokenEndpointAuthSigningAlg(?string $tokenEndpointAuthSigningAlg): void
    {
        $this->tokenEndpointAuthSigningAlg = $tokenEndpointAuthSigningAlg;
    }

    /**
     * @return int|null
     */
    public function getDefaultMaxAge(): ?int
    {
        return $this->defaultMaxAge;
    }

    /**
     * @param int|null $defaultMaxAge
     */
    public function setDefaultMaxAge(?int $defaultMaxAge): void
    {
        $this->defaultMaxAge = $defaultMaxAge;
    }

    /**
     * @return bool|null
     */
    public function getRequireAuthTime(): ?bool
    {
        return $this->requireAuthTime;
    }

    /**
     * @param bool|null $requireAuthTime
     */
    public function setRequireAuthTime(?bool $requireAuthTime): void
    {
        $this->requireAuthTime = $requireAuthTime;
    }

    /**
     * @return null|string[]
     */
    public function getDefaultAcrValues(): ?array
    {
        return $this->defaultAcrValues;
    }

    /**
     * @param null|string[] $defaultAcrValues
     */
    public function setDefaultAcrValues(?array $defaultAcrValues): void
    {
        $this->defaultAcrValues = $defaultAcrValues;
    }

    /**
     * @return null|string
     */
    public function getInitiateLoginUri(): ?string
    {
        return $this->initiateLoginUri;
    }

    /**
     * @param null|string $initiateLoginUri
     */
    public function setInitiateLoginUri(?string $initiateLoginUri): void
    {
        $this->initiateLoginUri = $initiateLoginUri;
    }

    /**
     * @return null|string[]
     */
    public function getRequestUris(): ?array
    {
        return $this->requestUris;
    }

    /**
     * @param null|string[] $requestUris
     */
    public function setRequestUris(?array $requestUris): void
    {
        $this->requestUris = $requestUris;
    }

}
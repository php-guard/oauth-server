<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 23:37
 */

namespace OAuth2\Roles\Clients;

class ClientMetadata implements ClientMetadataInterface
{
    /**
     * @var array|null
     */
    protected $redirectUris;

    /**
     * @var string|null
     */
    protected $tokenEndpointAuthMethod;

    /**
     * @var array|null
     */
    protected $grantTypes;

    /**
     * @var array|null
     */
    protected $responseTypes;

    /**
     * @var string|null
     */
    protected $clientName;

    /**
     * @var string|null
     */
    protected $clientUri;

    /**
     * @var string|null
     */
    protected $logoUri;

    /**
     * @var string|null
     */
    protected $scope;

    /**
     * @var array|null
     */
    protected $contacts;

    /**
     * @var string|null
     */
    protected $tosUri;

    /**
     * @var string|null
     */
    protected $policyUri;

    /**
     * @var string|null
     */
    protected $jwksUri;

    /**
     * @var array|null
     */
    protected $jwks;

    /**
     * @var string|null
     */
    protected $softwareId;

    /**
     * @var string|null
     */
    protected $softwareVersion;

    /**
     * @return array|null
     */
    public function getRedirectUris(): ?array
    {
        return $this->redirectUris;
    }

    /**
     * @param array|null $redirectUris
     */
    public function setRedirectUris(?array $redirectUris): void
    {
        $this->redirectUris = $redirectUris;
    }

    /**
     * @return null|string
     */
    public function getTokenEndpointAuthMethod(): ?string
    {
        return $this->tokenEndpointAuthMethod;
    }

    /**
     * @param null|string $tokenEndpointAuthMethod
     */
    public function setTokenEndpointAuthMethod(?string $tokenEndpointAuthMethod): void
    {
        $this->tokenEndpointAuthMethod = $tokenEndpointAuthMethod;
    }

    /**
     * @return array|null
     */
    public function getGrantTypes(): ?array
    {
        return $this->grantTypes;
    }

    /**
     * @param array|null $grantTypes
     */
    public function setGrantTypes(?array $grantTypes): void
    {
        $this->grantTypes = $grantTypes;
    }

    /**
     * @return array|null
     */
    public function getResponseTypes(): ?array
    {
        return $this->responseTypes;
    }

    /**
     * @param array|null $responseTypes
     */
    public function setResponseTypes(?array $responseTypes): void
    {
        $this->responseTypes = $responseTypes;
    }

    /**
     * @return null|string
     */
    public function getClientName(): ?string
    {
        return $this->clientName;
    }

    /**
     * @param null|string $clientName
     */
    public function setClientName(?string $clientName): void
    {
        $this->clientName = $clientName;
    }

    /**
     * @return null|string
     */
    public function getClientUri(): ?string
    {
        return $this->clientUri;
    }

    /**
     * @param null|string $clientUri
     */
    public function setClientUri(?string $clientUri): void
    {
        $this->clientUri = $clientUri;
    }

    /**
     * @return null|string
     */
    public function getLogoUri(): ?string
    {
        return $this->logoUri;
    }

    /**
     * @param null|string $logoUri
     */
    public function setLogoUri(?string $logoUri): void
    {
        $this->logoUri = $logoUri;
    }

    /**
     * @return null|string
     */
    public function getScope(): ?string
    {
        return $this->scope;
    }

    /**
     * @param null|string $scope
     */
    public function setScope(?string $scope): void
    {
        $this->scope = $scope;
    }

    /**
     * @return array|null
     */
    public function getContacts(): ?array
    {
        return $this->contacts;
    }

    /**
     * @param array|null $contacts
     */
    public function setContacts(?array $contacts): void
    {
        $this->contacts = $contacts;
    }

    /**
     * @return null|string
     */
    public function getTosUri(): ?string
    {
        return $this->tosUri;
    }

    /**
     * @param null|string $tosUri
     */
    public function setTosUri(?string $tosUri): void
    {
        $this->tosUri = $tosUri;
    }

    /**
     * @return null|string
     */
    public function getPolicyUri(): ?string
    {
        return $this->policyUri;
    }

    /**
     * @param null|string $policyUri
     */
    public function setPolicyUri(?string $policyUri): void
    {
        $this->policyUri = $policyUri;
    }

    /**
     * @return null|string
     */
    public function getJwksUri(): ?string
    {
        return $this->jwksUri;
    }

    /**
     * @param null|string $jwksUri
     */
    public function setJwksUri(?string $jwksUri): void
    {
        $this->jwksUri = $jwksUri;
    }

    /**
     * @return array|null
     */
    public function getJwks(): ?array
    {
        return $this->jwks;
    }

    /**
     * @param array|null $jwks
     */
    public function setJwks(?array $jwks): void
    {
        $this->jwks = $jwks;
    }

    /**
     * @return null|string
     */
    public function getSoftwareId(): ?string
    {
        return $this->softwareId;
    }

    /**
     * @param null|string $softwareId
     */
    public function setSoftwareId(?string $softwareId): void
    {
        $this->softwareId = $softwareId;
    }

    /**
     * @return null|string
     */
    public function getSoftwareVersion(): ?string
    {
        return $this->softwareVersion;
    }

    /**
     * @param null|string $softwareVersion
     */
    public function setSoftwareVersion(?string $softwareVersion): void
    {
        $this->softwareVersion = $softwareVersion;
    }
}
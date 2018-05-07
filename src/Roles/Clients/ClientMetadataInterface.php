<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 15/03/2018
 * Time: 23:12
 */

namespace OAuth2\Roles\Clients;


interface ClientMetadataInterface
{
    /**
     * @return array|null
     */
    function getRedirectUris(): ?array;
    /**
     * @return null|string
     */
    function getTokenEndpointAuthMethod(): ?string;

    /**
     * @return array|null
     */
    function getGrantTypes(): ?array;

    /**
     * @return array|null
     */
    function getResponseTypes(): ?array;
    /**
     * @return null|string
     */
    function getClientName(): ?string;

    /**
     * @return null|string
     */
    function getClientUri(): ?string;

    /**
     * @return null|string
     */
    function getLogoUri(): ?string;

    /**
     * @return null|string
     */
    function getScope(): ?string;

    /**
     * @return array|null
     */
    function getContacts(): ?array;
    /**
     * @return null|string
     */
    function getTosUri(): ?string;

    /**
     * @return null|string
     */
    function getPolicyUri(): ?string;

    /**
     * @return null|string
     */
    function getJwksUri(): ?string;

    /**
     * @return array|null
     */
    function getJwks(): ?array;

    /**
     * @return null|string
     */
    function getSoftwareId(): ?string;

    /**
     * @return null|string
     */
    function getSoftwareVersion(): ?string;
}
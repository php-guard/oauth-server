<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 15/03/2018
 * Time: 21:56
 */

namespace OAuth2\Extensions\OpenID;


use OAuth2\ScopePolicy\Policies\ScopePolicyInterface;

class Config extends \OAuth2\Config
{
    /**
     * @var string
     */
    private $issuerIdentifier;

    /**
     * @var int
     */
    protected $idTokenLifetime = 1800;

    public function __construct(ScopePolicyInterface $scopePolicy, string $issuerIdentifier)
    {
        parent::__construct($scopePolicy);
        $this->issuerIdentifier = $issuerIdentifier;
    }

    /**
     * @return string
     */
    public function getIssuerIdentifier(): string
    {
        return $this->issuerIdentifier;
    }

    /**
     * @param string $issuerIdentifier
     */
    public function setIssuerIdentifier(string $issuerIdentifier): void
    {
        $this->issuerIdentifier = $issuerIdentifier;
    }

    /**
     * @return int
     */
    public function getIdTokenLifetime(): int
    {
        return $this->idTokenLifetime;
    }

    /**
     * @param int $idTokenLifetime
     */
    public function setIdTokenLifetime(int $idTokenLifetime): void
    {
        $this->idTokenLifetime = $idTokenLifetime;
    }
}
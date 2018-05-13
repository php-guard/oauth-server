<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 22:28
 */

namespace OAuth2;


use OAuth2\ScopePolicy\Policies\DefaultScopePolicy;
use OAuth2\ScopePolicy\Policies\ScopePolicyInterface;

class Config
{
    /**
     * @var array
     */
//    protected $defaultScopes = [];

    /**
     * @var ScopePolicyInterface
     */
    protected $scopePolicy;
    /**
     * @var DefaultScopePolicy
     */
//    private $defaultScopePolicy;

    public function __construct(ScopePolicyInterface $scopePolicy)
    {
        $this->scopePolicy = $scopePolicy;
    }

    /**
     * @return array
     */
//    public function getDefaultScopes(): array
//    {
//        return $this->defaultScopes;
//    }

    /**
     * @param array $defaultScopes
     */
//    public function setDefaultScopes(array $defaultScopes): void
//    {
//        $this->defaultScopes = $defaultScopes;
//        $this->defaultScopePolicy->setScopes($defaultScopes);
//    }

    /**
     * @return ScopePolicyInterface
     */
    public function getScopePolicy(): ScopePolicyInterface
    {
        return $this->scopePolicy;
    }

    /**
     * @param ScopePolicyInterface $scopePolicy
     */
    public function setScopePolicy(ScopePolicyInterface $scopePolicy): void
    {
        $this->scopePolicy = $scopePolicy;
    }
}
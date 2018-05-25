<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 22:28
 */

namespace OAuth2;



use OAuth2\ScopePolicy\Policies\ScopePolicyInterface;

class Config
{
    /**
     * @var ScopePolicyInterface
     */
    protected $scopePolicy;

    /**
     * @var bool
     */
    protected $issueNewRefreshToken = true;

    /**
     * @var bool
     */
    protected $revokeOldRefreshToken = true;

    /**
     * @var bool
     */
    protected $revokeTokensWhenAuthorizationCodeIsReused = true;

    public function __construct(ScopePolicyInterface $scopePolicy)
    {
        $this->scopePolicy = $scopePolicy;
    }

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

    /**
     * @return bool
     */
    public function mayIssueNewRefreshToken(): bool
    {
        return $this->issueNewRefreshToken;
    }

    /**
     * @param bool $issueNewRefreshToken
     */
    public function setIssueNewRefreshToken(bool $issueNewRefreshToken): void
    {
        if($issueNewRefreshToken) {
            $this->setRevokeOldRefreshToken(true);
        }
        $this->issueNewRefreshToken = $issueNewRefreshToken;
    }

    /**
     * @return bool
     */
    public function mayRevokeOldRefreshToken(): bool
    {
        return $this->revokeOldRefreshToken;
    }

    /**
     * @param bool $revokeOldRefreshToken
     */
    public function setRevokeOldRefreshToken(bool $revokeOldRefreshToken): void
    {
        $this->revokeOldRefreshToken = $revokeOldRefreshToken;
    }

    /**
     * @return bool
     */
    public function shouldRevokeTokensWhenAuthorizationCodeIsReused(): bool
    {
        return $this->revokeTokensWhenAuthorizationCodeIsReused;
    }

    /**
     * @param bool $revokeTokensWhenAuthorizationCodeIsReused
     */
    public function setRevokeTokensWhenAuthorizationCodeIsReused(bool $revokeTokensWhenAuthorizationCodeIsReused): void
    {
        $this->revokeTokensWhenAuthorizationCodeIsReused = $revokeTokensWhenAuthorizationCodeIsReused;
    }
}
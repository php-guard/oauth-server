<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 06/03/2018
 * Time: 22:28
 */

namespace OAuth2;


use OAuth2\ScopePolicy\Policies\ErrorScopePolicy;
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

    public function __construct()
    {
        $this->scopePolicy = new ErrorScopePolicy();
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
     * @return Config
     */
    public function setScopePolicy(ScopePolicyInterface $scopePolicy): self
    {
        $this->scopePolicy = $scopePolicy;
        return $this;
    }

    /**
     * @return bool
     */
    public function mayIssueNewRefreshToken(): bool
    {
        return $this->issueNewRefreshToken;
    }

    /**
     * @see https://tools.ietf.org/html/rfc6749#section-6
     * The authorization server MAY issue a new refresh token, in which case
     * the client MUST discard the old refresh token and replace it with the
     * new refresh token.
     *
     * @param bool $issueNewRefreshToken
     * @return Config
     */
    public function setIssueNewRefreshToken(bool $issueNewRefreshToken): self
    {
        $this->issueNewRefreshToken = $issueNewRefreshToken;
        return $this;
    }

    /**
     * @return bool
     */
    public function mayRevokeOldRefreshToken(): bool
    {
        return $this->revokeOldRefreshToken;
    }

    /**
     * @see https://tools.ietf.org/html/rfc6749#section-6
     * The authorization server MAY revoke the old
     * refresh token after issuing a new refresh token to the client.  If a
     * new refresh token is issued, the refresh token scope MUST be
     * identical to that of the refresh token included by the client in the
     * request.
     *
     * @param bool $revokeOldRefreshToken
     */
    public function setRevokeOldRefreshToken(bool $revokeOldRefreshToken): self
    {
        $this->revokeOldRefreshToken = $revokeOldRefreshToken;
        return $this;
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
    public function setRevokeTokensWhenAuthorizationCodeIsReused(bool $revokeTokensWhenAuthorizationCodeIsReused): self
    {
        $this->revokeTokensWhenAuthorizationCodeIsReused = $revokeTokensWhenAuthorizationCodeIsReused;
        return $this;
    }
}
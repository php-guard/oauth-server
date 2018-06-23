<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:14
 */

namespace OAuth2\Extensions\OpenID\Endpoints;


use OAuth2\Endpoints\Authorization\AuthorizationRequestBuilder;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Extensions\OpenID\IdTokenManager;
use OAuth2\IdTokenInterface;
use OAuth2\ResponseModes\ResponseModeManager;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeManager;
use OAuth2\Extensions\OpenID\Roles\ResourceOwnerInterface;
use OAuth2\Roles\AuthorizationServer\EndUserInterface;
use OAuth2\ScopePolicy\ScopePolicyManager;
use OAuth2\Storages\ClientStorageInterface;
use Psr\Http\Message\ResponseInterface;


class AuthorizationEndpoint extends \OAuth2\Endpoints\AuthorizationEndpoint
{
    const DISPLAY_PAGE = 'page';
    const DISPLAY_POPUP = 'popup';
    const DISPLAY_TOUCH = 'touch';
    const DISPLAY_WAP = 'wap';

    const PROMPT_NONE = 'none';
    const PROMPT_LOGIN = 'login';
    const PROMPT_CONSENT = 'consent';
    const PROMPT_SELECT_ACCOUNT = 'select_account';
    /**
     * @var string|null
     */
    private $nonce;
    /**
     * @var string|null
     */
    private $display;
    /**
     * @var string|null
     */
    private $prompt;
    /**
     * @var int|null
     */
    private $maxAge;
    /**
     * @var string[]|null
     */
    private $uiLocales;
    /**
     * @var IdTokenInterface|null
     */
    private $idTokenHint;
    /**
     * @var string|null
     */
    private $loginHint;
    /**
     * @var string[]|null
     */
    private $acrValues;

    public function __construct(AuthorizationRequestBuilder $authorizationRequestBuilder,
                                EndUserInterface $authorizationServerEndUser)
    {
        parent::__construct($authorizationRequestBuilder, $authorizationServerEndUser);
    }

    /**
     * @return null|ResponseInterface
     * @throws OAuthException
     */
    protected function verifyResourceOwner(): ?ResponseInterface
    {
        if (!$this->resourceOwner->isAuthenticated(self::PROMPT_LOGIN)) {
            if ($this->prompt == self::PROMPT_NONE) {
                throw new OAuthException('login_required');
            }

            // may throw interaction_required
            return $this->resourceOwner->authenticate($this->prompt == self::PROMPT_SELECT_ACCOUNT, $this->loginHint);
        }

        if ($this->idTokenHint) {
            // check if user associated to this id token is the current user.
//                var_dump($this->idTokenHint['sub']);die;
            if ($this->idTokenHint['sub'] !== $this->resourceOwner->getIdentifier()) {
                if ($this->prompt == self::PROMPT_NONE) {
                    throw new OAuthException('invalid_request');
                } else {
                    throw new OAuthException('login_required');
                }
            }
        }

        if ($this->prompt == self::PROMPT_NONE &&
            $this->resourceOwner->isInteractionRequiredForConsent($this)) {
            throw new OAuthException('interaction_required');
        }

        return null;
    }

    /**
     * @param array $requestData
     * @return null|ResponseInterface
     * @throws OAuthException
     */
    protected function verifyConsent(array $requestData): ?ResponseInterface
    {
        $consentGiven = $this->resourceOwner->hasGivenConsent($this->getClient(), $this->getScopes(),
            $this->prompt == self::PROMPT_CONSENT);

        if (is_null($consentGiven)) {
            if ($this->prompt == self::PROMPT_NONE) {
                throw new OAuthException('consent_required');
            }

            return $this->resourceOwner->obtainConsent($this, $requestData);
        }

        if (empty($consentGiven)) {
            throw new OAuthException('access_denied', 'The resource owner denied the request.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        return null;
    }

    /**
     * @param array $requestData
     * @throws OAuthException
     */
    protected function verifyRequestData(array $requestData)
    {
        parent::verifyRequestData($requestData);

        if (!in_array('openid', $this->getScopes())) {
            return;
        }

        $this->nonce = empty($requestData['nonce']) ? null : $requestData['nonce'];
        $this->display = empty($requestData['display']) ? null : $requestData['display'];
        $this->prompt = empty($requestData['prompt']) ? null : $requestData['prompt'];
        $this->maxAge = empty($requestData['max_age']) ? null : $requestData['max_age'];
        $this->uiLocales = empty($requestData['ui_locales']) ? null : explode(' ', $requestData['ui_locales']);

        if (!empty($requestData['id_token_hint'])) {
            try {
                $this->idTokenHint = $this->idTokenManager->decode($requestData['id_token_hint']);
            } catch (\Exception $exception) {
                throw new OAuthException('invalid_request', 'Failed to decode id_token_hint : ' . $exception->getMessage());
            }
        }

        $this->loginHint = empty($requestData['login_hint']) ? null : $requestData['login_hint'];
        $this->acrValues = empty($requestData['acr_values']) ? null : explode(' ', $requestData['acr_values']);
    }

    /**
     * @return string|null
     */
    public function getNonce(): ?string
    {
        return $this->nonce;
    }

    /**
     * @return null|string
     */
    public function getDisplay(): ?string
    {
        return $this->display;
    }

    /**
     * @return null|string
     */
    public function getPrompt(): ?string
    {
        return $this->prompt;
    }

    /**
     * @return int|null
     */
    public function getMaxAge(): ?int
    {
        return $this->maxAge;
    }

    /**
     * @return null|string[]
     */
    public function getUiLocales(): ?array
    {
        return $this->uiLocales;
    }

    /**
     * @return null|IdTokenInterface
     */
    public function getIdTokenHint(): ?IdTokenInterface
    {
        return $this->idTokenHint;
    }

    /**
     * @return null|string
     */
    public function getLoginHint(): ?string
    {
        return $this->loginHint;
    }

    /**
     * @return null|string[]
     */
    public function getAcrValues(): ?array
    {
        return $this->acrValues;
    }
}
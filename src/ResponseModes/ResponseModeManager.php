<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:52
 */

namespace OAuth2\ResponseModes;


class ResponseModeManager
{
    protected $responseModes = [];
    /**
     * @var ResponseModeInterface
     */
    private $defaultResponseMode;

    public function __construct(ResponseModeInterface $defaultResponseMode)
    {
        $this->defaultResponseMode = $defaultResponseMode;
    }

    public function addResponseMode(string $identifier, ResponseModeInterface $responseMode)
    {
        $this->responseModes[$identifier] = $responseMode;
    }

    public function getResponseMode(string $identifier): ?ResponseModeInterface
    {
        return $this->responseModes[$identifier] ?? null;
    }

    public function getDefaultResponseMode(): ResponseModeInterface
    {
        return $this->defaultResponseMode;
    }
}
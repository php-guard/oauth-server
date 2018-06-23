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

    public function setResponseMode(string $identifier, ResponseModeInterface $responseMode): self
    {
        $this->responseModes[$identifier] = $responseMode;
        return $this;
    }

    public function getResponseMode(string $identifier): ?ResponseModeInterface
    {
        return $this->responseModes[$identifier] ?? null;
    }
}
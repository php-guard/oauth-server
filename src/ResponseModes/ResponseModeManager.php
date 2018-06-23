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

    public function addResponseMode(string $identifier, ResponseModeInterface $responseMode)
    {
        $this->responseModes[$identifier] = $responseMode;
    }

    public function getResponseMode(string $identifier): ?ResponseModeInterface
    {
        return $this->responseModes[$identifier] ?? null;
    }
}
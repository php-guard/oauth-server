<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/03/2018
 * Time: 17:51
 */

namespace OAuth2OLD\Parameters;


use OAuth2\Endpoints\TokenEndpoint;

interface ParameterHandlerInterface
{
    public function handle(TokenEndpoint $tokenEndpoint, array $requestData);
}
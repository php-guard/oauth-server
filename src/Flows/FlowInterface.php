<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:08
 */

namespace OAuth2\Flows;


use OAuth2\ResponseTypes\ResponseTypeInterface;
use OAuth2\GrantTypes\GrantTypeInterface;

interface FlowInterface extends ResponseTypeInterface, GrantTypeInterface
{
    /**
     * @return string[]
     */
    function getResponseTypes(): array;

    /**
     * @return string[]
     */
    function getGrantTypes(): array;
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:57
 */

namespace OAuth2\AuthorizationGrantTypes\Flows;


use OAuth2\AuthorizationGrantTypes\GrantTypeManager;
use OAuth2\AuthorizationEndpointResponseTypes\ResponseTypeManager;

class FlowManager
{
    protected $flows = [];
    /**
     * @var ResponseTypeManager
     */
    private $responseTypeManager;
    /**
     * @var GrantTypeManager
     */
    private $grantTypeManager;

    public function __construct(ResponseTypeManager $responseTypeManager, GrantTypeManager $grantTypeManager)
    {
        $this->responseTypeManager = $responseTypeManager;
        $this->grantTypeManager = $grantTypeManager;
    }

    public function addFlow(FlowInterface $flow)
    {
        foreach ($flow->getResponseTypes() as $responseType) {
            $this->responseTypeManager->addResponseType($responseType, $flow);
        }

        foreach ($flow->getGrantTypes() as $grantType) {
            $this->grantTypeManager->addGrantType($grantType, $flow);
        }
    }
}
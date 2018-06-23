<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 21:06
 */

namespace OAuth2\Extensions\PKCE\Endpoints\Authorization;


use OAuth2\Exceptions\InvalidAuthorizationRequest;
use OAuth2\Exceptions\InvalidRequestMethod;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\ClientTypes\PublicClient;
use OAuth2\Roles\ResourceOwnerInterface;
use Psr\Http\Message\ServerRequestInterface;

class AuthorizationRequestBuilder extends \OAuth2\Endpoints\Authorization\AuthorizationRequestBuilder
{
    /**
     * @param ServerRequestInterface $request
     * @param ResourceOwnerInterface $resourceOwner
     * @return AuthorizationRequest
     * @throws InvalidRequestMethod
     * @throws OAuthException
     * @throws InvalidAuthorizationRequest
     */
    public function build(ServerRequestInterface $request, ResourceOwnerInterface $resourceOwner): \OAuth2\Endpoints\Authorization\AuthorizationRequest
    {
        $authorizationRequest = parent::build($request, $resourceOwner);

        try {
            $codeChallenge = $authorizationRequest->getData()['code_challenge'] ?? null;

            $codeChallengeMethod = 'plain';
            if(!empty($authorizationRequest->getData()['code_challenge_method'])) {
                $codeChallengeMethod = $authorizationRequest->getData()['code_challenge_method'];
            }

            if (empty($codeChallenge)) {
                if ($authorizationRequest->getClient() instanceof PublicClient) {
                    throw new OAuthException('invalid_request',
                        'The request is missing the required parameter code_challenge for public clients.',
                        'https://tools.ietf.org/html/rfc7636#section-4.4');
                }
                return $authorizationRequest;
            }

            if (!in_array($codeChallengeMethod, ['plain', 'S256'])) {
                throw new OAuthException('invalid_request',
                    'The request includes the invalid parameter code_challenge_method. Supported : plain, S256.',
                    'https://tools.ietf.org/html/rfc7636#section-4');
            }
        } catch (OAuthException $e) {
            throw new InvalidAuthorizationRequest($e, $authorizationRequest->getRedirectUri(),
                $authorizationRequest->getResponseMode(), $authorizationRequest->getState());
        }

        return new AuthorizationRequest($authorizationRequest, $codeChallenge, $codeChallengeMethod);
    }
}
<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 21:51
 */

namespace OAuth2\Tests\Extensions\PKCE;


use GuzzleHttp\Psr7\ServerRequest;


class TokenEndpointTest extends AuthorizationEndpointTest
{
    /**
     * @return mixed|\Psr\Http\Message\ResponseInterface
     * @throws \Exception
     */
    public function testAuthorizationCodeGrantTypeShouldReturnTokens()
    {
        list('code' => $code, 'code_verifier' => $codeVerifier) = $this->testCodeResponseTypeShouldReturnAuthorizationCode();

        /**
         * @see https://tools.ietf.org/html/rfc7636#section-4.5
         * Upon receipt of the Authorization Code, the client sends the Access
         * Token Request to the token endpoint.  In addition to the parameters
         * defined in the OAuth 2.0 Access Token Request (Section 4.1.3 of
         * [RFC6749]), it sends the following parameter:
         *
         * code_verifier
         * REQUIRED.  Code verifier
         *
         * The "code_challenge_method" is bound to the Authorization Code when
         * the Authorization Code is issued.  That is the method that the token
         * endpoint MUST use to verify the "code_verifier".
         */
        $request = new ServerRequest('POST', '');
        $request = $request->withParsedBody([
            'client_id' => $this->client->getIdentifier(),
            'client_secret' => $this->client->getPassword(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->client->getMetadata()->getRedirectUris()[0] ?? null,
            'code' => $code,
            'code_verifier' => $codeVerifier
        ]);
        $response = $this->server->getAuthorizationServer()->getTokenEndpoint()->handle($request);
        $json = $response->getBody()->__toString();
        $response = json_decode($json, true);
        $this->assertArrayHasKey('access_token', $response, $json);
        $this->assertArrayHasKey('token_type', $response, $json);
        $this->assertArrayHasKey('expires_in', $response, $json);
        $this->assertArrayHasKey('refresh_token', $response, $json);
        return $response;
    }
}
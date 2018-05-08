<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 17:45
 */

namespace OAuth2\Tests\Endpoints;

use GuzzleHttp\Psr7\ServerRequest;


class TokenEndpointTest extends AuthorizationEndpointTest
{
    public function testAuthorizationCodeGrantTypeShouldReturnTokens() {
        $code = $this->testCodeResponseTypeShouldReturnAuthorizationCode();

        $request = new ServerRequest('POST', '');
        $request = $request->withParsedBody([
            'client_id' => $this->client->getIdentifier(),
            'client_secret' => $this->client->getPassword(),
            'grant_type' => 'authorization_code',
            'redirect_uri' => $this->client->getMetadata()->getRedirectUris()[0] ?? null,
            'code' => $code,
        ]);
        $response = $this->server->getTokenEndpoint()->handleRequest($request);
        $json = $response->getBody()->__toString();
        $response = json_decode($json, true);
        $this->assertArrayHasKey('access_token', $response, $json);
        $this->assertArrayHasKey('token_type', $response, $json);
        $this->assertArrayHasKey('expires_in', $response, $json);
        $this->assertArrayHasKey('refresh_token', $response, $json);
        return $response;
    }

    public function testRefreshTokenGrantTypeShouldReturnTokens() {
        $tokens = $this->testAuthorizationCodeGrantTypeShouldReturnTokens();

        $request = new ServerRequest('POST', '');
        $request = $request->withParsedBody([
            'client_id' => $this->client->getIdentifier(),
            'client_secret' => $this->client->getPassword(),
            'grant_type' => 'refresh_token',
            'redirect_uri' => $this->client->getMetadata()->getRedirectUris()[0] ?? null,
            'refresh_token' => $tokens['refresh_token'],
        ]);

        $response = $this->server->getTokenEndpoint()->handleRequest($request);
        $json = $response->getBody()->__toString();
        $response = json_decode($json, true);

        $this->assertArrayHasKey('access_token', $response, $json);
        $this->assertArrayHasKey('token_type', $response, $json);
        $this->assertArrayHasKey('expires_in', $response, $json);
        $this->assertArrayHasKey('refresh_token', $response, $json);
        $this->assertNotEquals($tokens['access_token'], $response['access_token']);
        $this->assertNotEquals($tokens['refresh_token'], $response['refresh_token']);
    }

    public function testPasswordGrantTypeShouldReturnTokens() {
        $request = new ServerRequest('POST', '');
        $request = $request->withParsedBody([
            'client_id' => $this->client->getIdentifier(),
            'client_secret' => $this->client->getPassword(),
            'grant_type' => 'password',
            'username' => 'phpunit',
            'password' => 'password',
        ]);

        $response = $this->server->getTokenEndpoint()->handleRequest($request);
        $json = $response->getBody()->__toString();
        $response = json_decode($json, true);

        $this->assertArrayHasKey('access_token', $response, $json);
        $this->assertArrayHasKey('token_type', $response, $json);
        $this->assertArrayHasKey('expires_in', $response, $json);
        $this->assertArrayHasKey('refresh_token', $response, $json);
    }

    public function testClientCredentialsGrantTypeShouldReturnTokens() {
        $request = new ServerRequest('POST', '');
        $request = $request->withParsedBody([
            'client_id' => $this->client->getIdentifier(),
            'client_secret' => $this->client->getPassword(),
            'grant_type' => 'client_credentials'
        ]);

        $response = $this->server->getTokenEndpoint()->handleRequest($request);
        $json = $response->getBody()->__toString();
        $response = json_decode($json, true);

        $this->assertArrayHasKey('access_token', $response, $json);
        $this->assertArrayHasKey('token_type', $response, $json);
        $this->assertArrayHasKey('expires_in', $response, $json);
        $this->assertArrayNotHasKey('refresh_token', $response, $json);
    }
}
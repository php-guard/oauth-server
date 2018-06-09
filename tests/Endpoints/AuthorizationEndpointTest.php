<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/03/2018
 * Time: 17:45
 */

namespace OAuth2\Tests\Endpoints;

use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;


class AuthorizationEndpointTest extends Endpoint
{
    public function testCodeResponseTypeShouldReturnAuthorizationCode() {
        $request = new ServerRequest('GET', '');
        $request = $request->withQueryParams([
            'client_id' => $this->client->getIdentifier(),
            'redirect_uri' => $this->client->getMetadata()->getRedirectUris()[0] ?? null,
            'response_type' => 'code',
        ]);
        $response = $this->server->getAuthorizationServer()->getAuthorizationEndpoint()->handleRequest($request);
        $this->assertTrue($response->hasHeader('Location'));
        $location = new Uri($response->getHeader('Location')[0]);
        $response = [];
        parse_str($location->getQuery(), $response);
        $this->assertArrayHasKey('code', $response);
        return $response['code'];
    }

    public function testTokenResponseTypeShouldReturnAccessToken() {
        $request = new ServerRequest('GET', '');
        $request = $request->withQueryParams([
            'client_id' => $this->client->getIdentifier(),
            'redirect_uri' => $this->client->getMetadata()->getRedirectUris()[0] ?? null,
            'response_type' => 'token',
        ]);
        $response = $this->server->getAuthorizationServer()->getAuthorizationEndpoint()->handleRequest($request);
        $this->assertTrue($response->hasHeader('Location'));
        $location = new Uri($response->getHeader('Location')[0]);
        $response = [];
        parse_str($location->getFragment(), $response);
        $this->assertArrayHasKey('access_token', $response, $location->getFragment());
        $this->assertArrayHasKey('token_type', $response, $location->getFragment());
        $this->assertArrayHasKey('expires_in', $response, $location->getFragment());
        $this->assertEquals('bearer', $response['token_type']);
    }
}
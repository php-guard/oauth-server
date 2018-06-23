<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 11/06/2018
 * Time: 21:51
 */

namespace OAuth2\Tests\Extensions\PKCE;


use GuzzleHttp\Psr7\ServerRequest;
use GuzzleHttp\Psr7\Uri;
use OAuth2\Helper;
use OAuth2\Tests\Endpoints\Endpoint;

class AuthorizationEndpointTest extends Endpoint
{
    /**
     * @return mixed
     * @throws \Exception
     */
    public function testCodeResponseTypeShouldReturnAuthorizationCode()
    {
        /**
         * @see https://tools.ietf.org/html/rfc7636#section-4.1
         * The client first creates a code verifier, "code_verifier", for each
         * OAuth 2.0 [RFC6749] Authorization Request, in the following manner:
         *
         * code_verifier = high-entropy cryptographic random STRING using the
         * unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
         * from Section 2.3 of [RFC3986], with a minimum length of 43 characters
         * and a maximum length of 128 characters.
         *
         * ABNF for "code_verifier" is as follows.
         *
         * code-verifier = 43*128unreserved
         * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
         * ALPHA = %x41-5A / %x61-7A
         * DIGIT = %x30-39
         *
         * NOTE: The code verifier SHOULD have enough entropy to make it
         * impractical to guess the value.  It is RECOMMENDED that the output of
         * a suitable random number generator be used to create a 32-octet
         * sequence.  The octet sequence is then base64url-encoded to produce a
         * 43-octet URL safe string to use as the code verifier.
         */
        $codeVerifier = random_bytes(32);

        /**
         * @see https://tools.ietf.org/html/rfc7636#section-4.2
         * The client then creates a code challenge derived from the code
         * verifier by using one of the following transformations on the code
         * verifier:
         *
         * plain
         * code_challenge = code_verifier
         *
         * S256
         * code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
         *
         * If the client is capable of using "S256", it MUST use "S256", as
         * "S256" is Mandatory To Implement (MTI) on the server.  Clients are
         * permitted to use "plain" only if they cannot support "S256" for some
         * technical reason and know via out-of-band configuration that the
         * server supports "plain".
         *
         * The plain transformation is for compatibility with existing
         * deployments and for constrained environments that can't use the S256
         * transformation.
         *
         * ABNF for "code_challenge" is as follows.
         *
         * code-challenge = 43*128unreserved
         * unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
         * ALPHA = %x41-5A / %x61-7A
         * DIGIT = %x30-39
         */
        $codeChallenge = Helper::base64url_encode(hash('sha256', $codeVerifier));

        /**
         * @see https://tools.ietf.org/html/rfc7636#section-4.3
         *  The client sends the code challenge as part of the OAuth 2.0
         * Authorization Request (Section 4.1.1 of [RFC6749]) using the
         * following additional parameters:
         *
         * code_challenge
         * REQUIRED.  Code challenge.
         *
         * code_challenge_method
         * OPTIONAL, defaults to "plain" if not present in the request.  Code
         * verifier transformation method is "S256" or "plain".
         */
        $request = new ServerRequest('GET', '');
        $request = $request->withQueryParams([
            'client_id' => $this->client->getIdentifier(),
            'redirect_uri' => $this->client->getMetadata()->getRedirectUris()[0] ?? null,
            'response_type' => 'code',
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256'
        ]);
        $response = $this->server->getAuthorizationServer()->getAuthorizationEndpoint()->handle($request);
        $this->assertTrue($response->hasHeader('Location'));
        $location = new Uri($response->getHeader('Location')[0]);
        $response = [];
        parse_str($location->getQuery(), $response);
        $this->assertArrayHasKey('code', $response, json_encode($response));
        return ['code' => $response['code'], 'code_verifier' => $codeVerifier];
    }
}
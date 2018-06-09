<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 18:14
 */

namespace OAuth2\Endpoints;


use GuzzleHttp\Psr7\Response;
use OAuth2\Exceptions\InvalidAuthorizationRequest;
use OAuth2\Exceptions\InvalidRequestMethod;
use OAuth2\Exceptions\OAuthException;
use OAuth2\Roles\AuthorizationServer\EndUserInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;


/**
 * Class AuthorizationEndpoint
 * @package OAuth2\Endpoints
 *
 * @see https://tools.ietf.org/html/rfc6749#section-3.1
 * The authorization endpoint is used to interact with the resource
 * owner and obtain an authorization grant.  The authorization server
 * MUST first verify the identity of the resource owner.  The way in
 * which the authorization server authenticates the resource owner
 * (e.g., username and password login, session cookies) is beyond the
 * scope of this specification.
 *
 * The means through which the client obtains the location of the
 * authorization endpoint are beyond the scope of this specification,
 * but the location is typically provided in the service documentation.
 *
 * The endpoint URI MAY include an "application/x-www-form-urlencoded"
 * formatted (per Appendix B) query component ([RFC3986] Section 3.4),
 * which MUST be retained when adding additional query parameters.  The
 * endpoint URI MUST NOT include a fragment component.
 *
 * Since requests to the authorization endpoint result in user
 * authentication and the transmission of clear-text credentials (in the
 * HTTP response), the authorization server MUST require the use of TLS
 * as described in Section 1.6 when sending requests to the
 * authorization endpoint.
 *
 * The authorization server MUST support the use of the HTTP "GET"
 * method [RFC2616] for the authorization endpoint and MAY support the
 * use of the "POST" method as well.
 *
 * Parameters sent without a value MUST be treated as if they were
 * omitted from the request.  The authorization server MUST ignore
 * unrecognized request parameters.  Request and response parameters
 * MUST NOT be included more than once.
 */
class AuthorizationEndpoint implements EndpointInterface
{
    /**
     * @var AuthorizationRequestBuilder
     */
    private $authorizationRequestBuilder;
    /**
     * @var AuthorizationRequest|null
     */
    private $authorizationRequest = null;
    /**
     * @var EndUserInterface
     */
    private $authorizationServerEndUser;

    public function __construct(AuthorizationRequestBuilder $authorizationRequestBuilder,
                                EndUserInterface $authorizationServerEndUser)
    {
        $this->authorizationRequestBuilder = $authorizationRequestBuilder;
        $this->authorizationServerEndUser = $authorizationServerEndUser;
    }

    public function verifyRequest(ServerRequestInterface $request): ?ResponseInterface
    {
        try {
            if ($response = $this->verifyResourceOwner()) {
                return $response;
            }

            $this->authorizationRequest = $this->authorizationRequestBuilder
                ->build($request, $this->authorizationServerEndUser->getAuthenticatedResourceOwner());
        } catch (InvalidRequestMethod $e) {
            return new Response(404);
        } catch (OAuthException $e) {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
             * If the request fails due to a missing, invalid, or mismatching
             * redirection URI, or if the client identifier is missing or invalid,
             * the authorization server SHOULD inform the resource owner of the
             * error and MUST NOT automatically redirect the user-agent to the
             * invalid redirection URI.
             */
            return new Response(400, ['content-type' => 'application/json'], $e->jsonSerialize());
        } catch (InvalidAuthorizationRequest $e) {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-4.1.2.1
             * If the resource owner denies the access request or if the request
             * fails for reasons other than a missing or invalid redirection URI,
             * the authorization server informs the client by adding the following
             * parameters to the query component of the redirection URI using the
             * "application/x-www-form-urlencoded" format, per Appendix B:
             *
             * error
             * REQUIRED.  A single ASCII [USASCII] error code
             *
             * error_description
             * OPTIONAL.  Human-readable ASCII [USASCII] text providing
             * additional information, used to assist the client developer in
             * understanding the error that occurred.
             * Values for the "error_description" parameter MUST NOT include
             * characters outside the set %x20-21 / %x23-5B / %x5D-7E.
             *
             * error_uri
             * OPTIONAL.  A URI identifying a human-readable web page with
             * information about the error, used to provide the client
             * developer with additional information about the error.
             * Values for the "error_uri" parameter MUST conform to the
             * URI-reference syntax and thus MUST NOT include characters
             * outside the set %x21 / %x23-5B / %x5D-7E.
             *
             * state
             * REQUIRED if a "state" parameter was present in the client
             * authorization request.  The exact value received from the
             * client.
             *
             */
            $oauthException = $e->getOauthException();
            $responseData = [
                'error' => $oauthException->getError()
            ];

            if ($oauthException->getErrorDescription()) {
                $responseData['error_description'] = $oauthException->getErrorDescription();
            }

            if ($oauthException->getErrorUri()) {
                $responseData['error_uri'] = $oauthException->getErrorUri();
            }

            if (!empty($e->getState())) {
                $responseData['state'] = $e->getState();
            }

            return $e->getResponseMode()->buildResponse($e->getRedirectUri(), $responseData);
        }

        return null;
    }

    /**
     * @param ServerRequestInterface $request
     * @return ResponseInterface
     *
     * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
     * The client constructs the request URI by adding the following
     * parameters to the query component of the authorization endpoint URI
     * using the "application/x-www-form-urlencoded" format, per Appendix B:
     *
     * response_type
     * REQUIRED.  Value MUST be set to [desired response type].
     *
     * client_id
     * REQUIRED.  The client identifier as described in Section 2.2.
     *
     * redirect_uri
     * OPTIONAL.  As described in Section 3.1.2.
     *
     * scope
     * OPTIONAL.  The scope of the access request as described by
     * Section 3.3.
     *
     * state
     * RECOMMENDED.  An opaque value used by the client to maintain
     * state between the request and callback.  The authorization
     * server includes this value when redirecting the user-agent back
     * to the client.  The parameter SHOULD be used for preventing
     * cross-site request forgery as described in Section 10.12.
     */
    public function handleRequest(ServerRequestInterface $request): ResponseInterface
    {
        /**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
         * The authorization server validates the request to ensure that all
         * required parameters are present and valid.
         */
        if ($response = $this->verifyRequest($request)) {
            return $response;
        }

        if (is_null($this->authorizationRequest)) {
            throw new \LogicException();
        }

        try {
            /**
             * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
             * If the request is valid,
             * the authorization server authenticates the resource owner and obtains
             * an authorization decision (by asking the resource owner or by
             * establishing approval via other means).
             */
            if ($response = $this->verifyConsent($this->authorizationRequest)) {
                return $response;
            }

            $responseData = $this->authorizationRequest->getResponseType()
                ->handleAuthorizationRequest($this->authorizationRequest);
        } catch (OAuthException $e) {
            /**
             * If the Authorization Server encounters any error, it MUST return an error response, per Section 3.1.2.6.
             */
            $responseData = [
                'error' => $e->getError()
            ];
            if ($e->getErrorDescription()) {
                $responseData['error_description'] = $e->getErrorDescription();
            }
            if ($e->getErrorUri()) {
                $responseData['error_uri'] = $e->getErrorUri();
            }
        }

        if (!empty($this->state)) {
            $responseData['state'] = $this->state;
        }

        /**
         * @see https://tools.ietf.org/html/rfc6749#section-4.1.1
         * When a decision is established, the authorization server directs the
         * user-agent to the provided client redirection URI using an HTTP
         * redirection response, or by other means available to it via the
         * user-agent.
         */
        return $this->authorizationRequest->getResponseMode()
            ->buildResponse($this->authorizationRequest->getRedirectUri(), $responseData);
    }


    /**
     * @param AuthorizationRequest $authorizationRequest
     * @return null|ResponseInterface
     * @throws OAuthException
     */
    protected function verifyConsent(AuthorizationRequest $authorizationRequest): ?ResponseInterface
    {
        $consentGiven = $this->authorizationServerEndUser->hasGivenConsent($authorizationRequest->getClient(), $authorizationRequest->getScopes());
        if (is_null($consentGiven)) {
            return $this->authorizationServerEndUser->obtainConsent($authorizationRequest);
        }

        if (empty($consentGiven)) {
            throw new OAuthException('access_denied', 'The resource owner denied the request.',
                'https://tools.ietf.org/html/rfc6749#section-4.1');
        }

        return null;
    }

    protected function verifyResourceOwner(): ?ResponseInterface
    {
        if (!$this->authorizationServerEndUser->getAuthenticatedResourceOwner()) {
            return $this->authorizationServerEndUser->authenticateResourceOwner();
        }
        return null;
    }


    /**
     * @return AuthorizationRequest|null
     */
    public function getAuthorizationRequest(): ?AuthorizationRequest
    {
        return $this->authorizationRequest;
    }

    /**
     * @return EndUserInterface
     */
    public function getAuthorizationServerEndUser(): EndUserInterface
    {
        return $this->authorizationServerEndUser;
    }
}
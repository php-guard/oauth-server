<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 14/03/2018
 * Time: 21:48
 */

namespace OAuth2\Extensions\OpenID;

use Jose\Component\Core\JWKSet;
use Jose\Component\KeyManagement\JWKFactory;
use OAuth2\Credentials\AccessTokenInterface;
use OAuth2\Extensions\OpenID\Credentials\AuthorizationCodeInterface;
use OAuth2\Extensions\OpenID\Roles\Clients\ClientMetadataInterface;
use OAuth2\Helper;
use OAuth2\IdToken;
use OAuth2\IdTokenInterface;
use OAuth2\Roles\ClientInterface;
use OAuth2\Roles\ClientTypes\RegisteredClient;


class IdTokenManager
{
    const KEY = 'AZE'; // Keys storage ? manager ?

    /**
     * @var Config
     */
    private $config;

    public function __construct(Config $config)
    {
        $this->config = $config;
    }

    public function decode(string $idToken): IdTokenInterface
    {
        $claims = $this->jwt->decode($idToken, self::KEY, 'HS256');
        $idToken = new IdToken((array)$claims);
        return $idToken;
    }

    public function issueIdToken(RegisteredClient $client,
                                 string $resourceOwnerIdentifier,
                                 array $additionalClaims = []): string
    {
        $metadata = $client->getMetadata();

        $idToken = array_merge([
            'iss' => $this->config->getIssuerIdentifier(),
            'sub' => $resourceOwnerIdentifier,
            'aud' => $client->getIdentifier(),
            'exp' => time() + $this->config->getIdTokenLifetime(),
            'iat' => time()
        ], $additionalClaims);

        $alg = 'RS256';
        if ($metadata instanceof ClientMetadataInterface) {
            $alg = $metadata->getIdTokenSignedResponseAlg() ?: 'RS256';
        }

        $keys=[];
        $jwks = $metadata->getJwks();

        if (!empty($jwks)) {
            $jwks = JWKFactory::createFromValues($jwks);
            if ($jwks instanceof JWKSet) {
                foreach ($jwks->all() as $key) {
                    $keys[] = $key;
                }
            } else {
                $keys[] = $jwks;
            }
        }

        $jwku = $metadata->getJwksUri();
        if (!is_null($jwku)) {
            foreach (JWKFactory::createFromJKU($jwku) as $key) {
                $keys[] = $key;
            }
        }
        $jwkSet = new JWKSet($keys);

        $key = $jwkSet->selectKey('sig', $alg);


//var_dump($idToken);die;
        $jws = JWSFactory::createJWS($idToken);
        $jws = $jws->addSignatureInformation($key,
            [
                'alg' => $alg,
                'kid' => $key->get('kid')
            ]
        );
        $signer = Signer::createSigner([$alg]);

        // Then we sign
        $signer->sign($jws);

//        var_dump($jws->toCompactJSON(0));die;
//        echo '<pre>';
//        print_r($jws->getClaims());
//        print_r($jws->toCompactJSON(0));
//        echo '</pre>';die;

//        var_dump($jws->toJSON());
//        die;
//        $idToken = JWT::encode($idToken, $key, $alg);

        return $jws->toCompactJSON(0);
    }

    public function getCodeHash(ClientInterface $client, AuthorizationCodeInterface $authorizationCode)
    {
        return $this->getHash($client, $authorizationCode->getCode());
    }

    public function getAccessTokenHash(ClientInterface $client, AccessTokenInterface $accessToken)
    {
        return $this->getHash($client, $accessToken->getToken());
    }

    public function getHash(ClientInterface $client, $target)
    {
        $alg = 'RS256';
        $metadata = $client->getMetadata();
        if ($metadata instanceof ClientMetadataInterface) {
            $alg = $metadata->getIdTokenSignedResponseAlg() ?: 'RS256';
        }

        $macAlgorithm = substr($alg, -3);

        if (!in_array($macAlgorithm, [256, 384, 512])) {
            throw new \UnexpectedValueException('Client metadata Id token signed response alg value is unexpected. 
            It must end with "256", "384" or "513"');
        }
        $macAlgorithm = 'sha' . $macAlgorithm;

        $hash = hash($macAlgorithm, $target, true);
        $hash = substr($hash, 0, strlen($hash) / 2);
        return Helper::base64url_encode($hash);
    }
}
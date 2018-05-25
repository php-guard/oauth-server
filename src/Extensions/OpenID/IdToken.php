<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 17:51
 */

namespace OAuth2;


use Firebase\JWT\JWT;

class IdToken implements IdTokenInterface
{
    /**
     * @var array
     */
    protected $claims;

    /**
     * IdToken constructor.
     * @param array $claims
     * @throws \Exception
     */
    public function __construct(array $claims)
    {
//        $missingClaims = array_diff(self::REQUIRED_CLAIMS, array_keys($claims));
//        if (!empty($missingClaims)) {
//            throw new \Exception('Missing claims : ' . implode(', ', $missingClaims));
//        }

//        $undefinedClaims = array_diff(array_keys($claims), self::DEFINED_CLAIMS);
//        if (!empty($undefinedClaims)) {
//            throw new \Exception('Undefined claims : ' . implode(', ', $undefinedClaims));
//        }

        // todo check nonce required if present in authentication request
        // todo check auth_time if max_age request is made or auth_time is required via config

        $this->claims = $claims;
    }

public function getClaims() : array
    {
       return $this->claims;
    }

    /**
     * Specify data which should be serialized to JSON
     * @link http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize()
    {
        return JWT::encode($this->getClaims(), 'key');
    }
}
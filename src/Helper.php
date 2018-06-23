<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 10/03/2018
 * Time: 15:59
 */

namespace OAuth2;


abstract class Helper
{
    const CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"; // [A-Z] / [a-z] / [0-9]
    const LENGTH = 22;

    public static function containsNotAsciiChar(string $string)
    {
        return preg_match('/[^\x20-\x7e]/', $string);
    }

    /**
     * @param int $length
     * @return string
     * @throws \Exception
     */
    public static function generateToken($length = self::LENGTH)
    {
        $token = '';
        for ($i = 0; $i < $length; ++$i) {
            $token .= self::CHARS[random_int(0, strlen(self::CHARS) - 1)];
        }
        return $token;
    }

//    public static function pemToInline($pem)
//    {
//        $pem = str_replace('-----BEGIN PUBLIC KEY-----', '', $pem);
//        $pem = str_replace('-----END PUBLIC KEY-----', '', $pem);
//        $pem = str_replace("\n", '', $pem);
//        return $pem;
//    }

//    public static function certToArray($cert)
//    {
//        return [
//            'kty' => 'RSA',
//            'alg' => 'RSA256',
//            'use' => 'sig',
//            'kid' => $cert->getKid(),
//            'n' => $cert->getN(),
//            'e' => $cert->getE(),
//            'x5c' => self::pemToInline($cert->getPublicKey())
//        ];
//    }

//    public static function generateRSAKeys()
//    {
//        $config = array(
//            "digest_alg" => "sha512",
//            "private_key_bits" => 4096,
//            "private_key_type" => OPENSSL_KEYTYPE_RSA,
//        );
//        // Create the private and public key
//        $res = openssl_pkey_new($config);
//
//        // Extract the private key from $res to $privKey
//        openssl_pkey_export($res, $privKey);
//
//        // Extract the public key from $res to $pubKey
//        $details = openssl_pkey_get_details($res);
//
//        $pubKey = $details["key"];
//        return ['privKey' => $privKey, 'pubKey' => $pubKey, 'rsa' => $details['rsa']];
//    }

    /**
     * @param $data
     * @return string
     * @src https://gist.github.com/nathggns/6652997
     */
    public static function base64url_encode($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param      $data
     * @param bool $pad
     * @return bool|string
     * @src https://gist.github.com/nathggns/6652997
     */
    public static function base64url_decode($data, $pad = false)
    {
        $data = strtr($data, '-_', '+/');
        if ($pad) {
            $data = str_pad($data, strlen($data) + (4 - strlen($data) % 4) % 4);
        }
        return base64_decode($data);
    }

    public static function array_equals($a, $b) {
        return (
            is_array($a)
            && is_array($b)
            && count($a) == count($b)
            && array_diff($a, $b) === array_diff($b, $a)
        );
    }
}
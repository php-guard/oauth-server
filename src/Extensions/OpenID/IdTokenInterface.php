<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 18/02/2018
 * Time: 17:31
 */

namespace OAuth2;

interface IdTokenInterface extends JsonWebTokenInterface
{
    const DEFINED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'amr', 'azp'];
    const REQUIRED_CLAIMS = ['iss', 'sub', 'aud', 'exp', 'iat'];
    const STANDARD_CLAIMS = ['sub',
        'name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username',
        'profile', 'picture', 'website', 'email', 'email_verified', 'gender', 'birthdate',
        'zoneinfo', 'locale', 'phone_number', 'phone_number_verified', 'address', 'update_at'
    ];
}
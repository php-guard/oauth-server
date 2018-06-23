<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 29/01/2018
 * Time: 10:34
 */

namespace OAuth2OLD\OpenID\Storages;


use OAuth2\Roles\ResourceOwnerInterface;
use OAuth2OLD\OpenID\Models\StandardClaims;
use OAuth2OLD\Roles\ResourceOwnerInterface;
use OAuth2OLD\Storages\StorageInterface;

interface UserInfoClaimsStorage
{
    const PROFILE_CLAIMS = ['name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username',
        'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'];
    const EMAIL_CLAIMS = ['email', 'email_verified'];
    const ADDRESS_CLAIMS = ['formatted', 'street_address', 'locality', 'region', 'postal_code', 'country'];
    const PHONE_CLAIMS = ['phone_number', 'phone_number_verified'];

    public function getClaims(ResourceOwnerInterface $resourceOwner): StandardClaims;
    public function getClaimsByScope(?array $scope): array;
}
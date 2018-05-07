<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 29/01/2018
 * Time: 15:27
 */

namespace OAuth2OLD\OpenID\Models;


class StandardClaims implements \ArrayAccess
{
    /**
     * @var string
     */
    protected $sub;
    /**
     * @var null|string
     */
    protected $name;
    /**
     * @var null|string
     */
    protected $givenName;
    /**
     * @var null|string
     */
    protected $familyName;
    /**
     * @var null|string
     */
    protected $middleName;
    /**
     * @var null|string
     */
    protected $nickname;
    /**
     * @var null|string
     */
    protected $preferredUsername;
    /**
     * @var null|string
     */
    protected $profile;
    /**
     * @var null|string
     */
    protected $picture;
    /**
     * @var null|string
     */
    protected $website;
    /**
     * @var null|string
     */
    protected $email;
    /**
     * @var null|bool
     */
    protected $emailVerified;
    /**
     * @var null|string
     */
    protected $gender;
    /**
     * @var null|string
     */
    protected $birthdate;
    /**
     * @var null|string
     */
    protected $zoneinfo;
    /**
     * @var null|string
     */
    protected $locale;
    /**
     * @var null|string
     */
    protected $phoneNumber;
    /**
     * @var null|bool
     */
    protected $phoneNumberVerified;
    /**
     * @var null|AddressClaim
     */
    protected $address;
    /**
     * @var null|string
     */
    protected $updatedAt;
    
    public function __construct(string $sub)
    {
        $this->sub = $sub;
    }

    /**
     * @return string
     */
    public function getSub(): string
    {
        return $this->sub;
    }

    /**
     * @return null|string
     */
    public function getName(): ?string
    {
        return $this->name;
    }

    /**
     * @param null|string $name
     */
    public function setName(?string $name)
    {
        $this->name = $name;
    }

    /**
     * @return null|string
     */
    public function getGivenName(): ?string
    {
        return $this->givenName;
    }

    /**
     * @param null|string $givenName
     */
    public function setGivenName(?string $givenName)
    {
        $this->givenName = $givenName;
    }

    /**
     * @return null|string
     */
    public function getFamilyName(): ?string
    {
        return $this->familyName;
    }

    /**
     * @param null|string $familyName
     */
    public function setFamilyName(?string $familyName)
    {
        $this->familyName = $familyName;
    }

    /**
     * @return null|string
     */
    public function getMiddleName(): ?string
    {
        return $this->middleName;
    }

    /**
     * @param null|string $middleName
     */
    public function setMiddleName(?string $middleName)
    {
        $this->middleName = $middleName;
    }

    /**
     * @return null|string
     */
    public function getNickname(): ?string
    {
        return $this->nickname;
    }

    /**
     * @param null|string $nickname
     */
    public function setNickname(?string $nickname)
    {
        $this->nickname = $nickname;
    }

    /**
     * @return null|string
     */
    public function getPreferredUsername(): ?string
    {
        return $this->preferredUsername;
    }

    /**
     * @param null|string $preferredUsername
     */
    public function setPreferredUsername(?string $preferredUsername)
    {
        $this->preferredUsername = $preferredUsername;
    }

    /**
     * @return null|string
     */
    public function getProfile(): ?string
    {
        return $this->profile;
    }

    /**
     * @param null|string $profile
     */
    public function setProfile(?string $profile)
    {
        $this->profile = $profile;
    }

    /**
     * @return null|string
     */
    public function getPicture(): ?string
    {
        return $this->picture;
    }

    /**
     * @param null|string $picture
     */
    public function setPicture(?string $picture)
    {
        $this->picture = $picture;
    }

    /**
     * @return null|string
     */
    public function getWebsite(): ?string
    {
        return $this->website;
    }

    /**
     * @param null|string $website
     */
    public function setWebsite(?string $website)
    {
        $this->website = $website;
    }

    /**
     * @return null|string
     */
    public function getEmail(): ?string
    {
        return $this->email;
    }

    /**
     * @param null|string $email
     */
    public function setEmail(?string $email)
    {
        $this->email = $email;
    }

    /**
     * @return null|bool
     */
    public function getEmailVerified(): ?bool
    {
        return $this->emailVerified;
    }

    /**
     * @param null|bool $emailVerified
     */
    public function setEmailVerified(?bool $emailVerified)
    {
        $this->emailVerified = $emailVerified;
    }

    /**
     * @return null|string
     */
    public function getGender(): ?string
    {
        return $this->gender;
    }

    /**
     * @param null|string $gender
     */
    public function setGender(?string $gender)
    {
        $this->gender = $gender;
    }

    /**
     * @return null|string
     */
    public function getBirthdate(): ?string
    {
        return $this->birthdate;
    }

    /**
     * @param null|string $birthdate
     */
    public function setBirthdate(?string $birthdate)
    {
        $this->birthdate = $birthdate;
    }

    /**
     * @return null|string
     */
    public function getZoneinfo(): ?string
    {
        return $this->zoneinfo;
    }

    /**
     * @param null|string $zoneinfo
     */
    public function setZoneinfo(?string $zoneinfo)
    {
        $this->zoneinfo = $zoneinfo;
    }

    /**
     * @return null|string
     */
    public function getLocale(): ?string
    {
        return $this->locale;
    }

    /**
     * @param null|string $locale
     */
    public function setLocale(?string $locale)
    {
        $this->locale = $locale;
    }

    /**
     * @return null|string
     */
    public function getPhoneNumber(): ?string
    {
        return $this->phoneNumber;
    }

    /**
     * @param null|string $phoneNumber
     */
    public function setPhoneNumber(?string $phoneNumber)
    {
        $this->phoneNumber = $phoneNumber;
    }

    /**
     * @return null|bool
     */
    public function getPhoneNumberVerified(): ?bool
    {
        return $this->phoneNumberVerified;
    }

    /**
     * @param null|bool $phoneNumberVerified
     */
    public function setPhoneNumberVerified(?bool $phoneNumberVerified)
    {
        $this->phoneNumberVerified = $phoneNumberVerified;
    }

    /**
     * @return null|AddressClaim
     */
    public function getAddress(): ?AddressClaim
    {
        return $this->address;
    }

    /**
     * @param null|AddressClaim $address
     */
    public function setAddress(?AddressClaim $address)
    {
        $this->address = $address;
    }

    /**
     * @return null|string
     */
    public function getUpdatedAt(): ?string
    {
        return $this->updatedAt;
    }

    /**
     * @param null|string $updatedAt
     */
    public function setUpdatedAt(?string $updatedAt)
    {
        $this->updatedAt = $updatedAt;
    }

    private function snakeToCamel($offset) {
        return preg_replace_callback('/_(.?)/', function($matches) {
            return ucfirst($matches[1]);
        }, $offset);
    }

    /**
     * Whether a offset exists
     * @link http://php.net/manual/en/arrayaccess.offsetexists.php
     * @param mixed $offset <p>
     * An offset to check for.
     * </p>
     * @return boolean true on success or false on failure.
     * </p>
     * <p>
     * The return value will be casted to boolean if non-boolean was returned.
     * @since 5.0.0
     */
    public function offsetExists($offset)
    {
        return method_exists($this, 'get'.ucfirst($this->snakeToCamel($offset)));
    }

    /**
     * Offset to retrieve
     * @link http://php.net/manual/en/arrayaccess.offsetget.php
     * @param mixed $offset <p>
     * The offset to retrieve.
     * </p>
     * @return mixed Can return all value types.
     * @since 5.0.0
     */
    public function offsetGet($offset)
    {
        $getter = 'get'.ucfirst($this->snakeToCamel($offset));
        $result = $this->{$getter}();
        if(is_object($result)) {
            return json_encode($result);
        }
        return $result;
    }

    /**
     * Offset to set
     * @link http://php.net/manual/en/arrayaccess.offsetset.php
     * @param mixed $offset <p>
     * The offset to assign the value to.
     * </p>
     * @param mixed $value <p>
     * The value to set.
     * </p>
     * @return void
     * @since 5.0.0
     */
    public function offsetSet($offset, $value)
    {
        $setter = 'set'.ucfirst($this->snakeToCamel($offset));
        $this->{$setter}($value);
    }

    /**
     * Offset to unset
     * @link http://php.net/manual/en/arrayaccess.offsetunset.php
     * @param mixed $offset <p>
     * The offset to unset.
     * </p>
     * @return void
     * @since 5.0.0
     */
    public function offsetUnset($offset)
    {
        $setter = 'set'.ucfirst($this->snakeToCamel($offset));
        $this->{$setter}(null);
    }
}
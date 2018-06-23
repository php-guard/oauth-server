<?php
/**
 * Created by PhpStorm.
 * User: GCC-MED
 * Date: 29/01/2018
 * Time: 15:34
 */

namespace OAuth2OLD\OpenID\Models;


class AddressClaim implements \JsonSerializable
{
    /**
     * @var null|string
     */
    protected $formatted;
    /**
     * @var null|string
     */
    protected $streetAddress;
    /**
     * @var null|string
     */
    protected $locality;
    /**
     * @var null|string
     */
    protected $region;
    /**
     * @var string
     */
    protected $postalCode;
    /**
     * @var null|string
     */
    protected $country;

    /**
     * @return null|string
     */
    public function getFormatted(): ?string
    {
        return $this->formatted;
    }

    /**
     * @param null|string $formatted
     */
    public function setFormatted(?string $formatted)
    {
        $this->formatted = $formatted;
    }

    /**
     * @return null|string
     */
    public function getStreetAddress(): ?string
    {
        return $this->streetAddress;
    }

    /**
     * @param null|string $streetAddress
     */
    public function setStreetAddress(?string $streetAddress)
    {
        $this->streetAddress = $streetAddress;
    }

    /**
     * @return null|string
     */
    public function getLocality(): ?string
    {
        return $this->locality;
    }

    /**
     * @param null|string $locality
     */
    public function setLocality(?string $locality)
    {
        $this->locality = $locality;
    }

    /**
     * @return null|string
     */
    public function getRegion(): ?string
    {
        return $this->region;
    }

    /**
     * @param null|string $region
     */
    public function setRegion(?string $region)
    {
        $this->region = $region;
    }

    /**
     * @return null|string
     */
    public function getPostalCode(): ?string
    {
        return $this->postalCode;
    }

    /**
     * @param null|string $postalCode
     */
    public function setPostalCode(?string $postalCode)
    {
        $this->postalCode = $postalCode;
    }

    /**
     * @return null|string
     */
    public function getCountry(): ?string
    {
        return $this->country;
    }

    /**
     * @param null|string $country
     */
    public function setCountry(?string $country)
    {
        $this->country = $country;
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
        $data = [];
        if($this->formatted) {
            $data['formatted'] = $this->formatted;
        }
        if($this->streetAddress) {
            $data['street_address'] = $this->streetAddress;
        }
        if($this->locality) {
            $data['locality'] = $this->locality;
        }
        if($this->region) {
            $data['region'] = $this->region;
        }
        if($this->postalCode) {
            $data['postal_code'] = $this->postalCode;
        }
        if($this->country) {
            $data['country'] = $this->country;
        }
        return empty($data) ? '' : json_encode($data);
    }
}
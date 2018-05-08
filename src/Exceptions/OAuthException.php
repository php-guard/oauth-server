<?php
/**
 * Created by PhpStorm.
 * User: Alexandre
 * Date: 04/03/2018
 * Time: 17:40
 */

namespace OAuth2\Exceptions;


class OAuthException extends \Exception implements \JsonSerializable
{
    /**
     * @var string
     */
    private $error;
    /**
     * @var null|string
     */
    private $errorDescription;
    /**
     * @var null|string
     */
    private $errorUri;

    public function __construct(string $error, ?string $errorDescription = null, ?string $errorUri = null)
    {
        parent::__construct($errorDescription);
        $this->error = $error;
        $this->errorDescription = $errorDescription;
        $this->errorUri = $errorUri;
    }

    /**
     * @return string
     */
    public function getError(): string
    {
        return $this->error;
    }

    /**
     * @return null|string
     */
    public function getErrorDescription(): ?string
    {
        return $this->errorDescription;
    }

    /**
     * @return null|string
     */
    public function getErrorUri(): ?string
    {
        return $this->errorUri;
    }

    /**
     * Specify data which should be serialized to JSON
     * @link  http://php.net/manual/en/jsonserializable.jsonserialize.php
     * @return mixed data which can be serialized by <b>json_encode</b>,
     * which is a value of any type other than a resource.
     * @since 5.4.0
     */
    public function jsonSerialize()
    {
        $data = [
            'error' => $this->error
        ];
        if ($this->errorDescription) {
            $data['error_description'] = $this->errorDescription;
        }
        if ($this->errorUri) {
            $data['error_uri'] = $this->errorUri;
        }

        return json_encode($data);
    }
}
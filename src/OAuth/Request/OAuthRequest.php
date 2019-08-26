<?php declare(strict_types = 1);

namespace eureka2\OAuth\Request;

/**
 * This class represents an outgoing OAuth request to be sent to an OAuth provider.
 *
 */
class OAuthRequest {

	/**
	 * Url of the endpoint of the OAuth provider
	 *
	 * @var string
	 */
	private $url;

	/**
	 * HTTP method for the request
	 *
	 * @var string
	 */
	private $method;

	/**
	 * The request-header fields to pass additional information about the request, 
	 * and about the client itself, to the provider.
	 *
	 * @var array
	 */
	private $headers = [];

	/**
	 * The optional request body content
	 *
	 * @var string
	 */
	private $body = null;

	/**
	 * Constructs a OAuth request object 
	 *
	 * @param string $url url of the endpoint of the OAuth provider
	 * @param string $method HTTP method for the request.
	 * @param array $headers headers for the message.
	 * @param string|null $body the body content of the request.
	 */
	public function __construct($url, $method, $headers = [], $body = null) {
		$this->url = $url;
		$this->method = $method;
		$this->headers = $headers;
		$this->body = $body;
	}

	/**
	 * Returns the url of the endpoint of the OAuth provider
	 *
	 * @return string the url of the endpoint
	 */
	public function getUrl() {
		return $this->url;
	}

	/**
	 * Returns the HTTP method for the request
	 *
	 * @return string the HTTP method
	 */
	public function getMethod() {
		return $this->method;
	}

	/**
	 * Returns the request-header fields
	 *
	 * @return array the request-header fields
	 */
	public function getHeaders() {
		return $this->headers;
	}

	/**
	 * Returns the body content of the request
	 *
	 * @return string the body content
	 */
	public function getBody() {
		return $this->body;
	}

	/**
	 * Sets the url of the endpoint of the OAuth provider
	 *
	 * @param string url of the endpoint
	 *
	 * @return self
	 */
	public function setUrl($url) {
		$this->url = $url;
		return $this;
	}

	/**
	 * Sets the HTTP method for the request
	 *
	 * @param string the HTTP method
	 *
	 * @return self
	 */
	public function setMethod($method) {
		$this->method = $method;
		return $this;
	}

	/**
	 * Sets the request-header fields
	 *
	 * @param string the request-header fields
	 *
	 * @return self
	 */
	public function setHeaders($headers) {
		$this->headers = $headers;
		return $this;
	}

	/**
	 * Sets the body content of the request
	 *
	 * @param string the body content
	 *
	 * @return self
	 */
	public function setBody($body) {
		$this->body = $body;
		return $this;
	}

}

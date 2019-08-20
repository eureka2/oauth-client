<?php declare(strict_types = 1);

namespace eureka2\OAuth\Request;

class OAuthRequest {

	private $url;

	private $method;

	private $headers = [];

	private $body = null;

	public function __construct($url, $method, $headers = [], $body = null) {
		$this->url = $url;
		$this->method = $method;
		$this->headers = $headers;
		$this->body = $body;
	}

	public function getUrl() {
		return $this->url;
	}

	public function getMethod() {
		return $this->method;
	}

	public function getHeaders() {
		return $this->headers;
	}

	public function getBody() {
		return $this->body;
	}

	public function setUrl($url) {
		$this->url = $url;
		return $this;
	}

	public function setMethod($method) {
		$this->method = $method;
		return $this;
	}

	public function setHeaders($headers) {
		$this->headers = $headers;
		return $this;
	}

	public function setBody($body) {
		$this->body = $body;
		return $this;
	}

}

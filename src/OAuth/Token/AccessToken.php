<?php

namespace eureka2\OAuth\Token;

class AccessToken {

	/**
	 * @var string
	 */
	protected $value = '';

	/**
	 * @var int
	 */
	protected $secret = '';

	/**
	 * @var string
	 */
	protected $authorized = null;

	/**
	 * @var string
	 */
	protected $expiry = null;

	/**
	 * @var string
	 */
	protected $type = '';

	/**
	 * @var string
	 */
	protected $refresh = '';

	/**
	 * @var string
	 */
	protected $id_token = '';

	/**
	 * @var string
	 */
	protected $response = null;

	public function __construct($accessToken = []) {
		$this->setValue(isset($accessToken['value']) ? $accessToken['value'] : '');
		$this->setSecret(isset($accessToken['secret']) ? $accessToken['secret'] : '');
		$this->setAuthorized(isset($accessToken['authorized']) ? $accessToken['authorized'] : null);
		$this->setExpiry(isset($accessToken['expiry']) ? $accessToken['expiry'] : null);
		if (isset($accessToken['type'])) {
			$this->setType($accessToken['type']);
		}
		$this->setRefresh(isset($accessToken['refresh']) ? $accessToken['refresh'] : '');
		$this->setIdToken(isset($accessToken['id_token']) ? new IdToken($accessToken['id_token']) : null);
		$this->setResponse(isset($accessToken['response']) ? $accessToken['response'] : null);
	}

	public function getValue() {
		return $this->value;
	}

	public function getSecret() {
		return $this->secret;
	}

	public function getAuthorized() {
		return $this->authorized;
	}

	public function getExpiry() {
		return $this->expiry;
	}

	public function getType() {
		return $this->type;
	}

	public function getRefresh() {
		return $this->refresh;
	}

	public function getIdToken() {
		return $this->id_token;
	}

	public function getResponse() {
		return $this->response;
	}

	public function setValue($value) {
		$this->value = $value;
		return $this;
	}

	public function setSecret($secret) {
		$this->secret = $secret;
		return $this;
	}

	public function setAuthorized($authorized) {
		$this->authorized = $authorized;
		return $this;
	}

	public function setExpiry($expiry) {
		$this->expiry = $expiry;
		return $this;
	}

	public function setType($type) {
		$this->type = $type;
		return $this;
	}

	public function setRefresh($refresh) {
		$this->refresh = $refresh;
		return $this;
	}

	public function setIdToken($id_token) {
		$this->id_token = $id_token;
		return $this;
	}

	public function setResponse($response) {
		$this->response = $response;
		return $this;
	}

	public function __toString() {
		return $this->getValue();
	}

	public function toArray() {
		$accessToken = [
			'value' => $this->getValue(),
			'secret' => $this->getSecret()
		];
		if (!is_null($this->getAuthorized())) {
			$accessToken['authorized'] = $this->getAuthorized();
		}
		if (!is_null($this->getExpiry())) {
			$accessToken['expiry'] = $this->getExpiry();
		}
		if (!empty($this->getType())) {
			$accessToken['type'] = $this->getType();
		}
		if (!empty($this->getRefresh())) {
			$accessToken['refresh'] = $this->getRefresh();
		}
		if (!empty($this->getIdToken())) {
			$accessToken['id_token'] = $this->getIdToken()->toArray();
		}
		if (!is_null($this->getResponse())) {
			$accessToken['response'] = $this->getResponse();
		}
		return $accessToken;
	}

}
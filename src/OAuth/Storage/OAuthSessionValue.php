<?php declare(strict_types = 1);

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Token\AccessToken;

class OAuthSessionValue {

	private $id = null;
	private $sessionId = null;
	private $state = null;
	private $nonce = null;
	private $accessToken = null;
	private $provider = null;
	private $creation = null;
	private $user = null;

	public function __construct($oAuthSessionValue = []) {
		if (isset($oAuthSessionValue['id']) && !is_null($oAuthSessionValue['id'])) {
			$this->setId($oAuthSessionValue['id']);
		}
		if (isset($oAuthSessionValue['session']) && !is_null($oAuthSessionValue['session'])) {
			$this->setSession($oAuthSessionValue['session']);
		}
		if (isset($oAuthSessionValue['state']) && !is_null($oAuthSessionValue['state'])) {
			$this->setState($oAuthSessionValue['state']);
		}
		if (isset($oAuthSessionValue['nonce']) && !is_null($oAuthSessionValue['nonce'])) {
			$this->setNonce($oAuthSessionValue['nonce']);
		}
		if (isset($oAuthSessionValue['access_token']) && !is_null($oAuthSessionValue['access_token'])) {
			$this->setAccessToken(new AccessToken($oAuthSessionValue['access_token']));
		}
		if (isset($oAuthSessionValue['provider']) && !is_null($oAuthSessionValue['provider'])) {
			$this->setProvider($oAuthSessionValue['provider']);
		}
		if (isset($oAuthSessionValue['creation']) && !is_null($oAuthSessionValue['creation'])) {
			$this->setCreation($oAuthSessionValue['creation']);
		}
		if (isset($oAuthSessionValue['user']) && !is_null($oAuthSessionValue['user'])) {
			$this->setUser($oAuthSessionValue['user']);
		}
	}

	public function getId() {
		return $this->id;
	}

	public function getSessionId() {
		return $this->sessionId;
	}

	public function getState() {
		return $this->state;
	}

	public function getNonce() {
		return $this->nonce;
	}

	public function getAccessToken() {
		return $this->accessToken;
	}

	public function getProvider() {
		return $this->provider;
	}

	public function getCreation() {
		return $this->creation;
	}

	public function getUser() {
		return $this->user;
	}

	public function setId($id) {
		$this->id = $id;
		return $this;
	}

	public function setSession($sessionId) {
		$this->sessionId = $sessionId;
		return $this;
	}

	public function setState($state) {
		$this->state = $state;
		return $this;
	}

	public function setNonce($nonce) {
		$this->nonce = $nonce;
		return $this;
	}

	public function setAccessToken($accessToken) {
		$this->accessToken = $accessToken;
		return $this;
	}

	public function setProvider($provider) {
		$this->provider = $provider;
		return $this;
	}

	public function setCreation($creation) {
		$this->creation = $creation;
		return $this;
	}

	public function setUser($user) {
		$this->user = $user;
		return $this;
	}

	public function toArray() {
		$accessToken = $this->getAccessToken();
		return [
			'id' => $this->getId(),
			'session' => $this->getSessionId(),
			'state' => $this->getState(),
			'nonce' => $this->getNonce(),
			'access_token' => !is_null($accessToken) ? $accessToken->toArray() : [],
			'provider' => $this->getProvider(),
			'creation' => $this->getCreation(),
			'user' => $this->getUser()
		];
	}
}

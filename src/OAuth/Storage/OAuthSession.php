<?php declare(strict_types = 1);

/*
 * This file is part of the eureka2/oauth-client library.
 *
 * Copyright (c) 2019 Jacques Archimède
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Token\AccessToken;

/**
 * This class holds all the variables stored during a session
 *
 */
class OAuthSession {

	/**
	 * The serial number of the session used especially for database storage
	 *
	 * @var string $id
	 */
	private $id = null;

	/**
	 * The id of the session
	 *
	 * @var string $sessionId
	 */
	private $sessionId = null;

	/**
	 * The state parameter of authorization flow
	 *
	 * @var string $state
	 */
	private $state = null;

	/**
	 * The value used to mitigate replay attacks
	 *
	 * @var string $nonce
	 */
	private $nonce = null;

	/**
	 * The access token received from the provider
	 *
	 * @var \eureka2\OAuth\Token\AccessToken $accessToken
	 */
	private $accessToken = null;

	/**
	 * The name of the provider
	 *
	 * @var string $provider
	 */
	private $provider = null;

	/**
	 * The creation date of the session in '%Y-%m-%d %H:%M:%S' format
	 *
	 * @var string $creation
	 */
	private $creation = null;

	/**
	 * The user ID of the resource owner at the provider
	 *
	 * @var string $userId
	 */
	private $userId = null;

	/**
	 * Constructs a OAuthSession object from an array of session values
	 *
	 * @param array $OAuthSession array of session values
	 */
	public function __construct($oauthSession = []) {
		if (isset($oauthSession['id']) && !is_null($oauthSession['id'])) {
			$this->setId($oauthSession['id']);
		}
		if (isset($oauthSession['session']) && !is_null($oauthSession['session'])) {
			$this->setSession($oauthSession['session']);
		}
		if (isset($oauthSession['state']) && !is_null($oauthSession['state'])) {
			$this->setState($oauthSession['state']);
		}
		if (isset($oauthSession['nonce']) && !is_null($oauthSession['nonce'])) {
			$this->setNonce($oauthSession['nonce']);
		}
		if (isset($oauthSession['access_token']) && !is_null($oauthSession['access_token'])) {
			$this->setAccessToken(new AccessToken($oauthSession['access_token']));
		}
		if (isset($oauthSession['provider']) && !is_null($oauthSession['provider'])) {
			$this->setProvider($oauthSession['provider']);
		}
		if (isset($oauthSession['creation']) && !is_null($oauthSession['creation'])) {
			$this->setCreation($oauthSession['creation']);
		}
		if (isset($oauthSession['user']) && !is_null($oauthSession['user'])) {
			$this->setUserId($oauthSession['user']);
		}
	}

	/**
	 * Returns the serial number of the session
	 *
	 * @return string the serial number of the session
	 */
	public function getId() {
		return $this->id;
	}

	/**
	 * Returns the id of the session
	 *
	 * @return string the id of the session
	 */
	public function getSessionId() {
		return $this->sessionId;
	}

	/**
	 * Returns the state parameter of authorization flow
	 *
	 * @return string the state parameter
	 */
	public function getState() {
		return $this->state;
	}

	/**
	 * Returns the nonce used to mitigate replay attacks
	 *
	 * @return string the nonce
	 */
	public function getNonce() {
		return $this->nonce;
	}

	/**
	 * Returns the access token received from the provider
	 *
	 * @return \eureka2\OAuth\Token\AccessToken the access token
	 */
	public function getAccessToken() {
		return $this->accessToken;
	}

	/**
	 * Returns the name of the provider
	 *
	 * @return string the name of the provider
	 */
	public function getProvider() {
		return $this->provider;
	}

	/**
	 * Returns the creation date of the session in '%Y-%m-%d %H:%M:%S' format
	 *
	 * @return string the creation date of the session
	 */
	public function getCreation() {
		return $this->creation;
	}

	/**
	 * Returns the user ID of the resource owner
	 *
	 * @return string the user ID
	 */
	public function getUserId() {
		return $this->userId;
	}

	/**
	 * Sets the serial number of the session
	 *
	 * @param string $id the serial number of the session
	 *
	 * @return self
	 */
	public function setId($id) {
		$this->id = $id;
		return $this;
	}

	/**
	 * Sets the the id of the session
	 *
	 * @param string $sessionId the id of the session
	 *
	 * @return self
	 */
	public function setSession($sessionId) {
		$this->sessionId = $sessionId;
		return $this;
	}

	/**
	 * Sets the state parameter of authorization flow
	 *
	 * @param string $state the state parameter
	 *
	 * @return self
	 */
	public function setState($state) {
		$this->state = $state;
		return $this;
	}

	/**
	 * Sets the nonce used to mitigate replay attacks
	 *
	 * @param string $nonce the nonce
	 *
	 * @return self
	 */
	public function setNonce($nonce) {
		$this->nonce = $nonce;
		return $this;
	}

	/**
	 * Sets the access token received from the provider
	 *
	 * @param \eureka2\OAuth\Token\AccessToken $accessToken the access token
	 *
	 * @return self
	 */
	public function setAccessToken($accessToken) {
		$this->accessToken = $accessToken;
		return $this;
	}

	/**
	 * Sets the the name of the provider
	 *
	 * @param string $provider the name of the provider
	 *
	 * @return self
	 */
	public function setProvider($provider) {
		$this->provider = $provider;
		return $this;
	}

	/**
	 * Sets the creation date of the session in '%Y-%m-%d %H:%M:%S' format
	 *
	 * @param string $creation the creation date of the session
	 *
	 * @return self
	 */
	public function setCreation($creation) {
		$this->creation = $creation;
		return $this;
	}

	/**
	 * Sets the user ID of the resource owner
	 *
	 * @param string $userId the user ID
	 *
	 * @return self
	 */
	public function setUserId($userId) {
		$this->userId = $userId;
		return $this;
	}

	/**
	 * Converts the OAuthSession object to array
	 * 
	 * @return array of session values
	 */
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
			'user' => $this->getUserId()
		];
	}
}

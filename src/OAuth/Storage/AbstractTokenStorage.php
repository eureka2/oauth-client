<?php

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Token\AccessToken;
use eureka2\OAuth\Exception\OAuthClientException;

abstract class AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	protected $client = null;
	protected $parameters = null;

	protected $sessionId = '';
	protected $sessionPath = '/';

	public function __construct($client, $parameters = []) {
		$this->client = $client;
		$this->parameters = $parameters;
	}

	protected function getSessionId() {
		return $this->sessionId;
	}

	protected function getSessionCookieName() {
		return strtolower($this->client->getProvider()->getName()) . '_oauth_session';
	}

	protected function getSessionCookie() {
		return $_COOKIE[$this->getSessionCookieName()] ?? '';
	}

	protected function getSessionPath() {
		return $this->sessionPath;
	}

	protected function setSessionId($sessionId) {
		$this->sessionId = $sessionId;
		return $this;
	}

	protected function setSessionPath($sessionPath) {
		$this->sessionPath = $sessionPath;
		return $this;
	}

	protected function deleteSessionCookie() {
		unset($_COOKIE[$this->getSessionCookieName()]);
		setcookie($this->getSessionCookieName(), '', time() - 3600);
	}

	protected function initializeOAuthSession(&$session) {
		$session = new OauthSessionValue();
		$session->setState(md5(time() . rand()));
		$session->setNonce(uniqid($session->getState()));
		$session->setSession(md5($session->getState() . time() . rand()));
		$session->setProvider($this->client->getProvider()->getName());
		$session->setCreation(gmstrftime("%Y-%m-%d %H:%M:%S"));
	}

	protected function setupSession(&$session) {
		if (!empty($this->getSessionId()) || !empty($this->getSessionCookie())) {
			$this->client->trace(!empty($this->getSessionId()) ? 'Checking OAuth session ' . $this->getSessionId() : 'Checking OAuth session from cookie ' . $this->getSessionCookie());
			if (!$this->getOAuthSession(!empty($this->getSessionId()) ? $this->getSessionId() : $this->getSessionCookie(), $this->client->getProvider()->getName(), $session)) {
				throw new OAuthClientException('OAuth session error');
			}
		} else {
			$this->client->trace('No OAuth session is set');
			$session = null;
		}
		if (!isset($session)) {
			$this->client->trace('Creating a new OAuth session');
			if (!$this->createOAuthSession($session)) {
				throw new OAuthClientException('OAuth session error');
			}
			setcookie($this->getSessionCookieName(), $session->getSessionId(), 0, $this->getSessionPath());
		}
		$this->setSessionId($session->getSessionId());
		return true;
	}

	/**
	 * @inheritdoc
	 */
	abstract public function createOAuthSession(&$session);

	/**
	 * @inheritdoc
	 */
	abstract public function getOAuthSession($session, $provider, &$oauthSession);

	/**
	 * @inheritdoc
	 */
	abstract public function saveOAuthSession($session);

	/**
	 * @inheritdoc
	 */
	public function storeAccessToken($accessToken) {
		$session = null;
		if (!$this->setupSession($session)) {
			return false;
		}
		$session->setAccessToken(new AccessToken($accessToken));
		return $this->saveOAuthSession($session);
	}

	/**
	 * @inheritdoc
	 */
	public function storeUser($user) {
		$session = null;
		if (!$this->setupSession($session)) {
			return false;
		}
		$session->setUser($user);
		return $this->saveOAuthSession($session);
	}

	/**
	 * @inheritdoc
	 */
	public function getStoredAccessToken() {
		$session = null;
		if (!$this->setupSession($session)) {
			return [];
		}
		$token = $session->getAccessToken();
		$accessToken = !is_null($token) ? $token->toArray() : [];
		return $accessToken;
	}

	/**
	 * @inheritdoc
	 */
	public function getStoredState() {
		$session = null;
		if (!$this->setupSession($session)) {
			return null;
		}
		return $session->getState();
	}

	/**
	 * @inheritdoc
	 */
	public function getStoredNonce() {
		$session = null;
		if (!$this->setupSession($session)) {
			return null;
		}
		return $session->getNonce();
	}

	/**
	 * @inheritdoc
	 */
	public function getStoredUser() {
		$session = null;
		if (!$this->setupSession($session)) {
			return null;
		}
		return $session->getUser();
	}

	/**
	 * @inheritdoc
	 */
	public function initialize() {
	}

	/**
	 * @inheritdoc
	 */
	public function finalize() {
	}

}

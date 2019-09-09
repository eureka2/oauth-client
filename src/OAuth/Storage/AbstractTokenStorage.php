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
use eureka2\OAuth\Exception\OAuthClientException;

/**
 * Base class for all token storage classes
 *
 */
abstract class AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	/**
	 * The Oauth client object using this storage.
	 *
	 * @var \eureka2\OAuth\Client\OAuthClientInterface
	 */
	protected $client = null;

	/**
	 * Parameters of this token storage.
	 *
	 * @var array
	 */
	protected $parameters = [];

	/**
	 * The id of the session
	 *
	 * @var string
	 */
	protected $sessionId = '';

	/**
	 * The path on the server in which the cookie will be available on.
	 * Default : / (the entire domain)
	 *
	 * @var string
	 */
	protected $sessionPath = '/';

	/**
	 * Constructs a token storage object derived from this class
	 *
	 * @param \eureka2\OAuth\Client\OAuthClientInterface $client
	 * @param array $parameters
	 * Possible key values are :
	 *
	 * - type
	 *   - session : usage of the superglobal $_SESSION to store the token 
	 *   - pdo : usage of a PDO database to store the token 
	 *   - cookie : usage of encrypted cookies to store the token 
	 *   - apcu : usage of the PHP APC User Cache (APCu) to store the token 
	 *
	 * - key (only for type = cookie) : the key used to encrypt the cookie
	 * - dsn (only for type = pdo) : the information required to connect to the database.
	 */
	public function __construct($client, $parameters = []) {
		$this->client = $client;
		$this->parameters = $parameters;
	}

	/**
	 * Returns the id of the session
	 *
	 * @return string the id of the session
	 */
	protected function getSessionId() {
		return $this->sessionId;
	}

	/**
	 * Returns the name of a cookie that will be used to store the session id
	 * regardless of the token storage system
	 *
	 * @return string the name of the cookie
	 */
	protected function getSessionCookieName() {
		return strtolower($this->client->getProvider()->getName()) . '_oauth_session';
	}

	/**
	 * Returns the session id stored in a cookie
	 * regardless of the token storage system
	 *
	 * @return string
	 */
	protected function getSessionCookie() {
		return $_COOKIE[$this->getSessionCookieName()] ?? '';
	}

	/**
	 * Returns the path on the server
	 * in which the cookie will be available on
	 *
	 * @return string the path on the server
	 */
	protected function getSessionPath() {
		return $this->sessionPath;
	}

	/**
	 * Sets the id of the session
	 *
	 * @param string $sessionId the id of the session
	 *
	 * @return self
	 */
	protected function setSessionId($sessionId) {
		$this->sessionId = $sessionId;
		return $this;
	}

	/**
	 * Sets the path on the server in which the cookie will be available on
	 *
	 * @param string $sessionPath the path on the server
	 *
	 * @return self
	 */
	protected function setSessionPath($sessionPath) {
		$this->sessionPath = $sessionPath;
		return $this;
	}

	/**
	 * Deletes the session cookie that holds the session id
	 *
	 */
	protected function deleteSessionCookie() {
		unset($_COOKIE[$this->getSessionCookieName()]);
		setcookie($this->getSessionCookieName(), '', time() - 3600);
	}

	/**
	 * Creates an OAuthSession object and initializes it.
	 *
	 * @return \eureka2\OAuth\Storage\OAuthSession the initialized OAuthSession object
	 */
	protected function initializeOAuthSession() {
		$session = new OAuthSession();
		$session->setState(md5(time() . rand()));
		$session->setNonce(uniqid($session->getState()));
		$session->setSession(md5($session->getState() . time() . rand()));
		$session->setProvider($this->client->getProvider()->getName());
		$session->setCreation(gmstrftime("%Y-%m-%d %H:%M:%S"));
		return $session;
	}

	/**
	 * Retrieves the OAuth session or create it if it does not exist
	 *
	 * @return \eureka2\OAuth\Storage\OAuthSession the OAuthSession object
	 */
	protected function fetchOAuthSession() {
		$session = null;
		if (!empty($this->getSessionId()) || !empty($this->getSessionCookie())) {
			$this->client->trace(!empty($this->getSessionId()) ? 'Checking OAuth session ' . $this->getSessionId() : 'Checking OAuth session from cookie ' . $this->getSessionCookie());
			if (!$this->getOAuthSession(!empty($this->getSessionId()) ? $this->getSessionId() : $this->getSessionCookie(), $this->client->getProvider()->getName(), $session)) {
				throw new OAuthClientException('OAuth session error');
			}
		} else {
			$this->client->trace('No OAuth session is set');
		}
		if (!isset($session)) {
			$this->client->trace('Creating a new OAuth session');
			if (!$this->createOAuthSession($session)) {
				throw new OAuthClientException('OAuth session error');
			}
			setcookie($this->getSessionCookieName(), $session->getSessionId(), 0, $this->getSessionPath());
			$this->addProviderInCookie();
		}
		$this->setSessionId($session->getSessionId());
		return $session;
	}

	/**
	 * Returns the OAuth configuration for all providers
	 * where the user has logged on.
	 *
	 * @return array the OAuth configuration by provider
	 */
	protected function getProvidersInCookie() {
		$providers = $_COOKIE['oauth_client_providers'] ?? '';
		$providers = unserialize(base64_decode($providers));
		if (!is_array($providers)) {
			$providers = [];
		}
		return $providers;
	}

	/**
	 * Adds the OAuth configuration of the current provider
	 * to the list of providers where the user has logged on.
	 *
	 * @return void
	 */
	protected function addProviderInCookie() {
		$providers = $this->getProvidersInCookie();
		$provider = $this->client->getProvider()->getName();
		$providers[$provider] = [
			'provider' => $this->client->getProvider()->toArray(),
			'strategy' => $this->client->getStrategy()->toArray(),
			'storage' => $this->parameters
		];
		$providers = base64_encode(serialize($providers));
		setcookie('oauth_client_providers', $providers, 0, $this->getSessionPath());
	}

	/**
	 * Removes the OAuth configuration of the current provider
	 * from the list of providers where the user has logged on.
	 *
	 * @return void
	 */
	protected function removeProviderFromCookie() {
		$providers = $this->getProvidersInCookie();
		$provider = $this->client->getProvider()->getName();
		if (array_key_exists($provider, $providers)) {
			unset($providers[$provider]);
			$providers = base64_encode(serialize($providers));
			$_COOKIE['oauth_client_providers'] = $providers;
			setcookie('oauth_client_providers', $providers, 0, $this->getSessionPath());
		}
	}

	/**
	 * {@inheritdoc}
	 */
	abstract public function createOAuthSession(&$session);

	/**
	 * {@inheritdoc}
	 */
	abstract public function getOAuthSession($session, $provider, &$oauthSession);

	/**
	 * {@inheritdoc}
	 */
	abstract public function saveOAuthSession($session);

	/**
	 * {@inheritdoc}
	 */
	public function storeAccessToken($accessToken) {
		if (($session = $this->fetchOAuthSession()) == null) {
			return false;
		}
		$session->setAccessToken(new AccessToken($accessToken));
		return $this->saveOAuthSession($session);
	}

	/**
	 * {@inheritdoc}
	 */
	public function storeUserid($userId) {
		if (($session = $this->fetchOAuthSession()) == null) {
			return false;
		}
		$session->setUserId($userId);
		return $this->saveOAuthSession($session);
	}

	/**
	 * {@inheritdoc}
	 */
	public function getStoredAccessToken() {
		if (($session = $this->fetchOAuthSession()) == null) {
			return [];
		}
		$token = $session->getAccessToken();
		$accessToken = !is_null($token) ? $token->toArray() : [];
		return $accessToken;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getStoredState() {
		if (($session = $this->fetchOAuthSession()) == null) {
			return null;
		}
		return $session->getState();
	}

	/**
	 * {@inheritdoc}
	 */
	public function getStoredNonce() {
		if (($session = $this->fetchOAuthSession()) == null) {
			return null;
		}
		return $session->getNonce();
	}

	/**
	 * {@inheritdoc}
	 */
	public function getStoredUserId() {
		if (($session = $this->fetchOAuthSession()) == null) {
			return null;
		}
		return $session->getUserId();
	}

}

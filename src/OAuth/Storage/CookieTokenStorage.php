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

use eureka2\OAuth\Exception\OAuthClientException;

/**
 *
 * This class uses encrypted cookies
 * to store the OAuth session variables. 
 *
 * This class is instantiated if the 'storage' option is set as follows:
 * 'storage' => [
 *    'type' => 'cookie',
 *    'key' => '< A KEY STRING FOR ENCRYPTION >'
 * ]
 *
 */
class CookieTokenStorage
	extends AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	/**
	 * Holds the decrypted value of the cookie storing the OAuth session
	 *
	 * @var \eureka2\OAuth\Storage\OAuthSession the decrypted OAuth session
	 */
	private $cookieValue = null;

	/**
	 * Returns the name of the cookie used to store the OAuth session
	 *
	 * @var string the name of the cookie
	 */
	public function getCookieName() {
		return $this->getSessionCookieName() . '_storage';
	}

	/**
	 * Returns the encrypted OAuth session stored in the cookie
	 *
	 * @var string the encrypted OAuth session
	 */
	protected function getCookie() {
		return $_COOKIE[$this->getCookieName()] ?? '';
	}

	/**
	 * Returns the decrypted value of the cookie storing the OAuth session
	 *
	 * @return \eureka2\OAuth\Storage\OAuthSession|null
	 */
	protected function getCookieValue() {
		return $this->cookieValue;
	}

	/**
	 * Sets the decrypted value of the cookie storing the OAuth session
	 *
	 * @param \eureka2\OAuth\Storage\OAuthSession|null $cookieValue
	 *
	 * @return self
	 */
	protected function setCookieValue($cookieValue) {
		$this->cookieValue = $cookieValue;
		return $this;
	}

	/**
	 * Deletes the cookie that stores the OAuth session
	 */
	protected function deleteCookie() {
		unset($_COOKIE[$this->getCookieName()]);
		setcookie($this->getCookieName(), '', time() - 3600);
	}

	/**
	 * {@inheritdoc}
	 */
	public function createOAuthSession(&$session) {
		$session = $this->initializeOAuthSession();
		if (!$this->serialize($session)) {
			return false;
		}
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getOAuthSession($sessionId, $provider, &$oauthSession) {
		$value = $this->unserialize();
		if (!isset($value)) {
			$this->client->trace('Could not decrypt the OAuth session cookie');
			$oauthSession = null;
		} else {
			$oauthSession = $value;
		}
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function saveOAuthSession($session) {
		$this->serialize($session);
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function resetAccessToken() {
		$this->client->trace('Resetting the access token status for the OAuth provider ' . $this->client->getProvider()->getName());
		$this->deleteCookie();
		$this->deleteSessionCookie();
		$this->removeProviderFromCookie();
		return true;
	}

	/**
	 * Encrypts a string using the cookie encryption key provided
	 * at initialization of this class.
	 *
	 * @param string $text
	 *
	 * @return string the encrypted string
	 *
	 * @throws \eureka2\OAuth\Exception\OAuthClientException if the cookie encryption key is missing
	 */
	protected function encrypt($text) {
		if (!isset($this->parameters['key']) || empty($this->parameters['key'])) {
			throw new OAuthClientException('the cookie encryption key is missing');
		}
		$encodeTime = time();
		$key = $encodeTime . $this->parameters['key'];
		$method = 'AES-128-CBC';
		$ivlen = openssl_cipher_iv_length($method);
		$iv = openssl_random_pseudo_bytes($ivlen);
		$cipher = openssl_encrypt($text, $method, $key, OPENSSL_RAW_DATA, $iv);
		$hmac = hash_hmac('sha256', $cipher, $key, true);
		return base64_encode( $iv.$hmac.$cipher) . ':' . $encodeTime;
	}

	/**
	 * Decrypts a string using the cookie encryption key provided
	 * at initialization of this class.
	 *
	 * @param string $encrypted the encrypted string
	 *
	 * @return string|null the decrypted string or null
	 *
	 * @throws \eureka2\OAuth\Exception\OAuthClientException if the cookie encryption key is missing
	 */
	protected function decrypt($encrypted) {
		if (!isset($this->parameters['key']) || empty($this->parameters['key'])) {
			throw new OAuthClientException('the cookie encryption key is missing');
		}
		if (gettype($colon = strpos($encrypted, ':')) != 'integer'
			|| ($encodeTime = intval(substr($encrypted, $colon + 1))) == 0 
			|| $encodeTime > time() 
			|| !($encrypted = base64_decode(substr($encrypted, 0, $colon)))) {
			throw new OAuthClientException('invalid encrypted data to decode: ' . $encrypted);
		}
		$key = $encodeTime . $this->parameters['key'];
		$method = 'AES-128-CBC';
		$ivlen = openssl_cipher_iv_length($method);
		$iv = substr($encrypted, 0, $ivlen);
		$hmac = substr($encrypted, $ivlen, 32);
		$cipher = substr($encrypted, $ivlen + 32);
		$decrypted = openssl_decrypt($cipher, $method, $key, OPENSSL_RAW_DATA, $iv);
		$calcmac = hash_hmac('sha256', $cipher, $key, true);
		return hash_equals($hmac, $calcmac) ? $decrypted : null;
	}

	/**
	 * Unserializes, after decryption, the OAuth session stored in cookie
	 * then creates a OAuthSession object and returns it.
	 *
	 * @return \eureka2\OAuth\Storage\OAuthSession|null the unserialized OAuth session or null
	 */
	private function unserialize() {
		if (!is_null($this->getCookieValue())) {
			return $this->getCookieValue();
		}
		if (empty($this->getCookie())) {
			return null;
		}
		$decrypted = $this->decrypt($this->getCookie());
		if ($decrypted === null) {
			return null;
		}
		$value = unserialize($decrypted);
		$value = new OAuthSession($value);
		$this->setCookieValue($value);
		return $value;
	}

	/**
	 * Serializes, after encryption, the OAuthSession object given in argument
	 * then stores it in a cookie.
	 *
	 * @param \eureka2\OAuth\Storage\OAuthSession $value the OAuthSession object to serialize
	 *
	 * @return bool true if success, false if the OAuthSession object cannot be encrypted
	 */
	private function serialize($value) {
		$encrypted = $this->encrypt(serialize($value->toArray()));
		if ($encrypted === null) {
			return false;
		}
		$this->setCookieValue($value);
		setcookie($this->getCookieName(), $encrypted);
		return true;
	}

}

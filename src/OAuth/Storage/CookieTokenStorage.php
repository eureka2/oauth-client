<?php

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Client\OAuthClient;
use eureka2\OAuth\Client\OAuthClientInterface;
use eureka2\OAuth\Exception\OAuthClientException;

class CookieTokenStorage
	extends AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	private $cookieValue = null;

	public function getCookieName() {
		return $this->getSessionCookieName() . '_storage';
	}

	protected function getCookie() {
		return $_COOKIE[$this->getCookieName()] ?? '';
	}

	protected function getCookieValue() {
		return $this->cookieValue;
	}

	protected function setCookieValue($cookieValue) {
		$this->cookieValue = $cookieValue;
		return $this;
	}

	protected function deleteCookie() {
		unset($_COOKIE[$this->getCookieName()]);
		setcookie($this->getCookieName(), '', time() - 3600);
	}

	public function createOAuthSession(&$session) {
		$session = null;
		$this->initializeOAuthSession($session);
		if (!$this->serialize($session)) {
			return false;
		}
		return true;
	}

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

	public function saveOAuthSession($session) {
		$this->serialize($session);
		return true;
	}

	public function resetAccessToken() {
		$this->client->trace('Resetting the access token status for the OAuth provider ' . $provider);
		$this->deleteCookie();
		$this->deleteSessionCookie();
		return true;
	}

	protected function encrypt($text, &$encrypted) {
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
		$encrypted = base64_encode( $iv.$hmac.$cipher) . ':' . $encodeTime;
		return true;
	}

	protected function decrypt($encoded, &$encodeTime, &$decrypted) {
		if (!isset($this->parameters['key']) || empty($this->parameters['key'])) {
			throw new OAuthClientException('the cookie encryption key is empty');
		}
		if (gettype($colon = strpos($encoded, ':')) != 'integer'
			|| ($encodeTime = intval(substr($encoded, $colon + 1))) == 0 
			|| $encodeTime > time() 
			|| !($encrypted = base64_decode(substr($encoded, 0, $colon)))) {
			throw new OAuthClientException('invalid encrypted data to decode: ' . $encoded);
		}
		$key = $encodeTime . $this->parameters['key'];
		$method = 'AES-128-CBC';
		$ivlen = openssl_cipher_iv_length($method);
		$iv = substr($encrypted, 0, $ivlen);
		$hmac = substr($encrypted, $ivlen, 32);
		$cipher = substr($encrypted, $ivlen + 32);
		$decrypted = openssl_decrypt($cipher, $method, $key, OPENSSL_RAW_DATA, $iv);
		$calcmac = hash_hmac('sha256', $cipher, $key, true);
		return hash_equals($hmac, $calcmac);
	}

	private function unserialize() {
		if (!is_null($this->getCookieValue())) {
			return $this->getCookieValue();
		}
		if (empty($this->getCookie())) {
			return null;
		}
		if (!$this->decrypt($this->getCookie(), $encodeTime, $serialized)) {
			return null;
		}
		$value = unserialize($serialized);
		$value = new OAuthSessionValue($value);
		$this->setCookieValue($value);
		return $value;
	}

	private function serialize($value) {
		if (!$this->encrypt(serialize($value->toArray()), $encrypted)) {
			return false;
		}
		$this->setCookieValue($value);
		setcookie($this->getCookieName(), $encrypted);
		return true;
	}

}

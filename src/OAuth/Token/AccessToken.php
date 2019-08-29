<?php declare(strict_types = 1);

namespace eureka2\OAuth\Token;

/**
 * This class represents the access token response
 * returned by the authorization server.
 */
class AccessToken {

	/**
	 * @var string $value
	 * The access token string as issued by the authorization server.
	 */
	protected $value = '';

	/**
	 * @var string $secret
	 * For OAuth 1.0, used for exchange, signature generation, or refreshing the access_token
	 */
	protected $secret = '';

	/**
	 * @var bool $authorized
	 * For OAuth 1.0, determines if the OAuth token is authorized or not.
	 * For OAuth 2.0, this value is always true.
	 */
	protected $authorized = true;

	/**
	 * @var string $expiry
	 * The expiration date time of the access token (format: %Y-%m-%d %H:%M:%S)
	 * calculated from the lifetime in seconds of the token.
	 * If the access token expires, the server should reply with the duration
	 * of time the access token is granted for
	 */
	protected $expiry = '';

	/**
	 * @var string $type
	 * The type of token this is, typically just the string “bearer”.
	 */
	protected $type = '';

	/**
	 * @var string $refresh
	 * a refresh token which applications can use to obtain another access token
	 * when the access token will expire.
	 */
	protected $refresh = '';

	/**
	 * @var string $scope
	 * the granted scope when it is different from the requested scope,
	 * such as if the user modified the scope.
	 */
	protected $scope = '';

	/**
	 * @var \eureka2\OAuth\Token\IdToken|null  $id_token
	 * The OpenID token that the authorization server will return
	 * which encodes the user’s authentication information.
	 */
	protected $id_token = null;

	/**
	 * @var string|null $response
	 * the access token response as returned by the authorization server
	 */
	protected $response = null;

	/**
	 * Constructs a AccessToken object from an array
	 *
	 * @param array $accessToken
	 */
	public function __construct($accessToken = []) {
		$this->setValue(isset($accessToken['value']) ? $accessToken['value'] : '');
		$this->setSecret(isset($accessToken['secret']) ? $accessToken['secret'] : '');
		$this->setAuthorized(isset($accessToken['authorized']) ? $accessToken['authorized'] : true);
		$this->setExpiry(isset($accessToken['expiry']) ? $accessToken['expiry'] : '');
		if (isset($accessToken['type'])) {
			$this->setType($accessToken['type']);
		}
		$this->setRefresh(isset($accessToken['refresh']) ? $accessToken['refresh'] : '');
		$this->setScope(isset($accessToken['scope']) ? $accessToken['scope'] : '');
		$this->setIdToken(isset($accessToken['id_token']) ? $accessToken['id_token'] : null);
		$this->setResponse(isset($accessToken['response']) ? $accessToken['response'] : null);
	}

	/**
	 * Returns the access token string as issued by the authorization server.
	 * 
	 * @return string the access token string
	 */
	public function getValue() {
		return $this->value;
	}

	/**
	 * Returns the access token secret.
	 * For OAuth 1.0, used for exchange, signature generation, or refreshing the access_token.
	 * Unused for other versions.
	 * 
	 * @return string the access token secret
	 */
	public function getSecret() {
		return $this->secret;
	}

	/**
	 * Is the OAuth token is authorized?
	 * For OAuth 2.0, this value is always true.
	 * 
	 * @return bool true if the OAuth token is authorized, false otherwise.
	 */
	public function isAuthorized() {
		return $this->authorized;
	}

	/**
	 * Returns the expiration date time of the access token (format: %Y-%m-%d %H:%M:%S)
	 * calculated from the lifetime in seconds of the token.
	 * 
	 * @return string the expiration date time
	 */
	public function getExpiry() {
		return $this->expiry;
	}

	/**
	 * Returns the type of token which is, typically just the string “bearer”.
	 * 
	 * @return string the type of token
	 */
	public function getType() {
		return $this->type;
	}

	/**
	 * Returns the refresh token which applications can use to obtain another access token
	 * when the access token will expire.
	 * 
	 * @return string the refresh token
	 */
	public function getRefresh() {
		return $this->refresh;
	}

	/**
	 * Returns the granted scope when it is different from the requested scope,
	 * such as if the user modified the scope.
	 * 
	 * @return string the granted scope
	 */
	public function getScope() {
		return $this->scope;
	}

	/**
	 * Returns the OpenID token that the authorization server will return
	 * which encodes the user’s authentication information.
	 * 
	 * @return \eureka2\OAuth\Token\IdToken|null the ID token or null if there is no ID token.
	 */
	public function getIdToken() {
		return $this->id_token;
	}

	/**
	 * Returns the access token response as returned by the authorization server
	 * 
	 * @return string|null the access token response
	 */
	public function getResponse() {
		return $this->response;
	}

	/**
	 * Sets the access token string as issued by the authorization server.
	 *
	 * @param string $value the access token string
	 *
	 * @return self
	 */
	public function setValue($value) {
		$this->value = $value;
		return $this;
	}

	/**
	 * Sets the access token secret.
	 * For OAuth 1.0, used for exchange, signature generation, or refreshing the access_token.
	 * Unused for other versions.
	 *
	 * @param string $secret the access token secret
	 * 
	 * @return self
	 */
	public function setSecret($secret) {
		$this->secret = $secret;
		return $this;
	}

	/**
	 * Determines if the OAuth token is authorized or not.
	 * For OAuth 2.0, this value is always true.
	 *
	 * @param bool $authorized true if authorized, false otherwise
	 * 
	 * @return self
	 */
	public function setAuthorized($authorized) {
		$this->authorized = $authorized;
		return $this;
	}

	/**
	 * Sets the expiration date time of the access token (format: %Y-%m-%d %H:%M:%S)
	 * calculated from the lifetime in seconds of the token.
	 *
	 * @param string $expiry the expiration date time of the access token
	 * 
	 * @return self
	 */
	public function setExpiry($expiry) {
		$this->expiry = $expiry;
		return $this;
	}

	/**
	 * Sets the type of token which is, typically just the string “bearer”.
	 *
	 * @param string $type the type of token
	 * 
	 * @return self
	 */
	public function setType($type) {
		$this->type = $type;
		return $this;
	}

	/**
	 * Sets the refresh token which applications can use to obtain another access token
	 * when the access token will expire.
	 *
	 * @param string $refresh the refresh token
	 * 
	 * @return self
	 */
	public function setRefresh($refresh) {
		$this->refresh = $refresh;
		return $this;
	}

	/**
	 * Sets the granted scope when it is different from the requested scope,
	 * such as if the user modified the scope.
	 *
	 * @param string $scope the granted scope
	 * 
	 * @return self
	 */
	public function setScope($scope) {
		$this->scope = $scope;
		return $this;
	}

	/**
	 * Sets the OpenID token that the authorization server will return
	 * which encodes the user’s authentication information.
	 *
	 * @param \eureka2\OAuth\Token\IdToken|string|null $id_token the OpenID token
	 * 
	 * @return self
	 */
	public function setIdToken($id_token) {
		if ($id_token === null || empty($id_token)) {
			$this->id_token = null;
		} elseif ($id_token instanceof IdToken) {
			$this->id_token = $id_token;
		} else {
			$this->id_token = new IdToken($id_token);
		}
		return $this;
	}

	/**
	 * Sets the access token response as returned by the authorization server
	 *
	 * @param string $response the access token response
	 * 
	 * @return self
	 */
	public function setResponse($response) {
		$this->response = $response;
		return $this;
	}

	/**
	 * Returns the access token string as issued by the authorization server.
	 * Alias of getValue
	 * 
	 * @return string the access token string
	 */
	public function __toString() {
		return $this->getValue();
	}

	/**
	 * Converts the access token to array
	 * 
	 * @return array
	 */
	public function toArray() {
		$accessToken = [
			'value' => $this->getValue(),
			'secret' => $this->getSecret(),
			'authorized' => $this->isAuthorized()
		];
		if (!is_null($this->getExpiry())) {
			$accessToken['expiry'] = $this->getExpiry();
		}
		if (!empty($this->getType())) {
			$accessToken['type'] = $this->getType();
		}
		if (!empty($this->getRefresh())) {
			$accessToken['refresh'] = $this->getRefresh();
		}
		if (!empty($this->getScope())) {
			$accessToken['scope'] = $this->getScope();
		}
		if (!is_null($this->getIdToken())) {
			$accessToken['id_token'] = $this->getIdToken()->toArray();
		}
		if (!is_null($this->getResponse())) {
			$accessToken['response'] = $this->getResponse();
		}
		return $accessToken;
	}

}
<?php declare(strict_types = 1);

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Exception\OAuthClientAuthorizationException;
use eureka2\OAuth\Exception\OAuthClientException;
use eureka2\OAuth\Token\JWT;

class OAuth2Client extends AbstractOAuthClient implements OAuthClientInterface {

	protected function verifyClaims($jwt) {
		$claims = JWT::decode($jwt, 1);
		if ($claims->aud != $this->provider->getClientId()) {
			return false;
		}
		if (property_exists($claims, 'azp') && $claims->azp != $this->provider->getClientId()) {
			return false;
		}
		if (property_exists($claims, 'nonce') && $claims->nonce != $this->storage->getStoredNonce()) {
			return false;
		}
		if (!property_exists($claims, 'exp') || $claims->exp < time() - 300) {
			return false;
		}
		if (property_exists($claims, 'nbf') && $claims->nbf > time() + 300) {
			return false;
		}
		return $claims;
	}

	protected function verifySignature($jwt) {
		$header = JWT::decode($jwt);
		if (preg_match("/^RS(\d+)$/", $header->alg, $m)) {
			$digests = array_map(function($digest) {
				return strtolower($digest);
			}, openssl_get_md_methods());
			if (in_array('sha'.$m[1], $digests)) {
				$jwks = $this->provider->getJwksUri();
				if (empty($jwks)) {
					throw new OAuthClientException(
						sprintf(
							'jwks_uri is required for signature type: %s',
							$header->alg
						)
					);
				}
				$options = [
					'resource' => 'OAuth jwks',
					'fail_on_access_error' => true
				];
				if (($response = $this->sendOAuthRequest($jwks, 'GET', [], $options)) === false) {
					return false;
				}
				return JWT::verifyRSASignature($header, $response->keys, $jwt);
			}
		} elseif (preg_match("/^HS(\d+)$/", $header->alg, $m)) {
			$algos = array_map(function($algo) {
				return strtolower($algo);
			}, function_exists('hash_hmac_algos') ? hash_hmac_algos() : hash_algos());
			if (in_array('sha'.$m[1], $algos)) {
				return JWT::verifyHMACsignature($header, $jwt, $this->provider->getClientSecret());
			}
		}
		throw new OAuthClientException(
			sprintf(
				'No support for signature type: %s',
				$header->alg
			)
		);
	}

	protected function requestAnOAuthAccessToken($code, $refresh) {
		$redirectUri = $this->retrieveRedirectURI();
		$authentication = $this->strategy->getAccessTokenAuthentication();
		if (!empty($this->provider->getOauthUsername())) {
			$values = [
				'grant_type' => 'password',
				'username' => $this->provider->getOauthUsername(),
				'password' => $this->provider->getOauthPassword(),
				'redirect_uri' => $redirectUri
			];
			$authentication = 'Basic';
		} elseif ($this->provider->getRedirectUri() === 'oob' && !empty($this->provider->getPin())) {
			$values = [
				'grant_type' => 'pin',
				'pin' => $this->provider->getPin(),
				'scope' => $this->strategy->getScope(),
			];
		} elseif ($refresh) {
			$values = [
				'grant_type' => 'refresh_token',
				'refresh_token' => $this->getRefreshToken(),
				'scope' => $this->strategy->getScope(),
			];
			if (!empty($this->strategy->getRefreshTokenAuthentication())) {
				$authentication = $this->strategy->getRefreshTokenAuthentication();
			}
		} else {
			switch ($this->strategy->getGrantType()) {
				case 'password':
					throw new OAuthClientException('it was not specified the username for obtaining a password based OAuth 2 authorization');
				case 'authorization_code':
					$values = [
						'code' => $code,
						'redirect_uri' => $redirectUri,
						'grant_type' => 'authorization_code'
					];
					break;
				case 'client_credentials':
					$values = [
						'grant_type' => 'client_credentials'
					];
					$authentication = 'Basic';
					break;
				default:
					throw new OAuthClientException($this->strategy->getGrantType() . ' is not yet a supported OAuth 2 grant type');
			}
		}
		$options = [
			'resource' => 'OAuth ' . ($refresh ? 'refresh' : 'access') . ' token',
			'fail_on_access_error' => true,
			'convert_json_to_array' => true
		];
		if (!empty($accept = $this->strategy->getAccessTokenContentType())) {
			$options['accept'] = $accept;
		}
		if (!empty($language = $this->strategy->getAccessTokenLanguage())) {
			$options['accept_language'] = $language;
		}
		switch (strtolower($authentication)) {
			case 'basic':
			case 'none':
				$options['authentication'] = $authentication;
				break;
			case '':
				$values['client_id'] = $this->provider->getClientId();
				$values['client_secret'] = ($this->strategy->getTokenWithApiKey() ? $this->provider->getApiKey() : $this->provider->getClientSecret());
				break;
			default:
				throw new OAuthClientException($authentication . ' is not a supported authentication mechanism to retrieve an access token');
		}
		if (!empty($this->strategy->getAccessTokenContentType())) {
			$options['response_content_type'] = $this->strategy->getAccessTokenContentType();
		}
		if (($response = $this->sendOAuthRequest($this->getTokenEndpoint(), 'POST', $values, $options)) === false) {
			return false;
		}
		$this->setAccessToken('');
		if (isset($response[$name = 'access_token']) || isset($response[$name = 'AccessToken'])) {
			$this->setAccessToken($response[$name]);
		}
		if (isset($response['id_token']) && !empty($response['id_token'])) {
			$jwt = base64_decode($response['id_token']);
			if (!preg_match('/^((?U){[^}]+})((?U){[^}]+})?(.+)$/m', $jwt)) {
				throw new OAuthClientException('it was returned an invalid JSON Web Token for the id_token');
			}
			$this->setIdToken($response['id_token']);
			if (!$this->verifySignature($response['id_token'])) {
				throw new OAuthClientException('the signature of the returned id_token is not valid');
			}
			if (($claims = $this->verifyClaims($response['id_token'])) === false) {
				throw new OAuthClientException('the claims of the returned id_token is not valid');
			}
			if (property_exists($claims, 'sub')) {
				$this->storage->storeUser($claims->sub);
			}
		} 
		if (empty($this->storage->getStoredUser()) &&
			!empty($this->provider->getUserIdField()) &&
			!empty($this->provider->getUserinfoEndpoint())) {
			if (($user = $this->callAPI($this->provider->getUserinfoEndpoint(), 'GET', [], ['fail_on_access_error' => true, 'convert_json_to_array' => true])) !== false) {
				$field = $this->provider->getUserIdField();
				if (isset($user[$field])) {
					$this->storage->storeUser($user[$field]);
				}
			}
		}
		if (empty($this->getAccessToken())) {
			if ($this->getIdToken() === null) {
				if (isset($response['error'])) {
					throw new OAuthClientAuthorizationException('it was not possible to retrieve the access token: it was returned the error: ' . $response['error']);
				}
				throw new OAuthClientException('OAuth provider did not return the access token in the expected parameter');
			}
			$this->trace('The OAuth provider did not return an OAuth token but returned an id_token');
		}
		$accessToken = [
			'value' => $this->getAccessToken(),
			'authorized' => true,
		];
		if ($this->getIdToken() !== null) {
			$accessToken['id_token'] = $this->getIdToken();
		}
		if ($this->strategy->shouldStoreAccessTokenResponse()) {
			$accessToken['response'] = $response;
			$this->setAccessTokenResponse($response);
		}
		$this->trace('Access token: ' . (!empty($this->getAccessToken()) ? $this->getAccessToken() : 'Not retrieved'));
		if (isset($response['expires_in']) && $response['expires_in'] == 0) {
			$this->trace('Ignoring access token expiry set to 0');
			$this->setAccessTokenExpiry('');
		} elseif ((isset($response[$name = 'expires']) || isset($response[$name = 'Expires'])) || isset($response['expires_in'])) {
			$expires = (isset($response['expires_in']) ? $response['expires_in'] : $response[$name] - ($response[$name] > $this->getResponseTime() ? $this->getResponseTime() : 0));
			if (strval($expires) !== strval(intval($expires)) || $expires <= 0) {
				throw new OAuthClientException('OAuth provider did not return a supported type of access token expiry time');
			}
			$this->setAccessTokenExpiry(gmstrftime('%Y-%m-%d %H:%M:%S', $this->getResponseTime() + $expires));
			$this->trace('Access token expiry: ' . $this->getAccessTokenExpiry() . ' UTC');
			$accessToken['expiry'] = $this->getAccessTokenExpiry();
		} else {
			$this->setAccessTokenExpiry('');
		}
		if (isset($response['token_type'])) {
			$this->setAccessTokenType($response['token_type']);
			if (!empty($this->getAccessTokenType()) && $this->isDebug()) {
				$this->trace('Access token type: ' . $this->getAccessTokenType());
			}
			$accessToken['type'] = $this->getAccessTokenType();
		} else {
			$this->setAccessTokenType($this->strategy->getDefaultAccessTokenType());
			if (!empty($this->getAccessTokenType()) && $this->isDebug()) {
				$this->trace('Assumed the default for OAuth access token type which is ' . $this->getAccessTokenType());
			}
		}
		if (isset($response[$name = 'refresh_token']) || isset($response[$name = 'RefreshToken'])) {
			$this->setRefreshToken($response[$name]);
			$this->trace('Refresh token: ' . $this->getRefreshToken());
			$accessToken['refresh'] = $this->getRefreshToken();
		} elseif (!empty($this->getRefreshToken())) {
			$this->trace('Reusing previous refresh token: ' . $this->getRefreshToken());
			$accessToken['refresh'] = $this->getRefreshToken();
		}
		return $this->storage->storeAccessToken($accessToken);
	}

	public function callAPI($url, $method, $parameters, $options) {
		if (! $this->checkTokenBeforeCall($options)) {
			return false;
		}
		if (!isset($options['resource'])) {
			$options['resource'] = 'API call';
		}
		if (!isset($options['convert_json_to_array'])) {
			$options['convert_json_to_array'] = false;
		}
		if (strlen($this->getAccessTokenExpiry()) && strcmp($this->getAccessTokenExpiry(), gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0) {
			if (empty($this->getRefreshToken())) {
				throw new OAuthClientException('the access token expired and no refresh token is available');
			}
			$this->trace('Refreshing the OAuth access token expired on ' . $this->getAccessTokenExpiry());
			if (!$this->requestAnOAuthAccessToken(null, true)) {
				return false;
			}
		}
		if (strcasecmp($this->getAccessTokenType(), 'Bearer')) {
			$url .= (strcspn($url, '?') < strlen($url) ? '&' : '?') . (strlen($this->strategy->getAccessTokenParameter()) ? $this->strategy->getAccessTokenParameter() : 'access_token') . '=' . urlencode($this->getAccessToken());
		}
		return $this->sendOAuthRequest($url, $method, $parameters, $options);
	}

	protected function isAccessTokenExpired() {
		return !empty($this->getAccessTokenExpiry())
			&& strcmp($this->getAccessTokenExpiry(), gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0
			&& empty($this->getRefreshToken());
	}

	public function checkAccessToken(&$redirectUrl) {
		$this->checkNoToken();
		$this->trace('Checking if OAuth access token was already retrieved from ' . $this->getTokenEndpoint());
		if (!$this->isThereAStoredAccessToken()) {
			return false;
		}
		if ($this->isStoredAccessTokenValid()) {
			if (!$this->isAccessTokenExpired()) {
				return true;
			}
			$this->trace('The access token expired');
		} else {
			$this->trace('A valid access token is not available');
		}
		$redirectUrl = null;
		switch ($this->strategy->getGrantType()) {
			case 'authorization_code':
				if ($this->provider->getRedirectUri() === 'oob' && !empty($this->provider->getPin())) {
					$this->trace('Getting the access token using the pin');
					if (!$this->requestAnOAuthAccessToken(null, false)) {
						return false;
					}
					return true;
				} elseif (empty($this->provider->getOauthUsername())) {
					break;
				}
			case 'password':
				$this->trace('Getting the access token using the username and password');
				if (!$this->requestAnOAuthAccessToken(null, false)) {
					return false;
				}
				return true;
			case 'client_credentials':
				$this->trace('Getting the access token using the client credentials');
				if (!$this->requestAnOAuthAccessToken(null, false)) {
					return false;
				}
				return true;
			default:
				throw new OAuthClientException($this->strategy->getGrantType() . ' is not yet a supported OAuth 2 grant type');
		}
		$this->trace('Checking the authentication state');
		if (($storedState = $this->storage->getStoredState()) === null) {
			return false;
		}
		if (empty($storedState)) {
			throw new OAuthClientException('it was not set the OAuth state');
		}
		if (($state = $this->getRequestState()) === false) {
			return false;
		}
		if ($state === $storedState) {
			$this->trace('Checking the authentication code');
			$code = $this->getRequestCode();
			if (empty($code)) {
				$error = $this->getRequestError();
				if (!empty($error)) {
					throw new OAuthClientAuthorizationException($error);
				}
				throw new OAuthClientException('it was not returned the OAuth dialog code');
			}
			if (!$this->requestAnOAuthAccessToken($code, false)) {
				return false;
			}
		} else {
			$redirectUri = $this->retrieveRedirectURI();
			if (!empty($this->strategy->getAppendStateToRedirectUri())) {
				$redirectUri .= (strpos($redirectUri, '?') === false ? '?' : '&') . $this->strategy->getAppendStateToRedirectUri() . '=' . $storedState;
			}
			$storedNonce = $this->storage->getStoredNonce();
			$url = $this->getAuthorizationEndpoint($redirectUri, $storedState, $storedNonce);
			if (empty($url)) {
				throw new OAuthClientException('it was not set the OAuth authorization endpoint');
			}
			$redirectUrl = $url;
		}
		return true;
	}

}

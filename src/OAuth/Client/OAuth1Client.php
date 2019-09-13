<?php declare(strict_types = 1);

/*
 * This file is part of the eureka2/oauth-client library.
 *
 * Copyright (c) 2019 Jacques Archimède
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Exception\OAuthClientAuthorizationException;
use eureka2\OAuth\Exception\OAuthClientException;

/**
 * This class represents the OAuth client dealing with providers supporting OAuth 1.0 or OAuth 1.0a.
 */
class OAuth1Client extends AbstractOAuthClient implements OAuthClientInterface {

	/**
	 * Prepares and initiates the request for an access token
	 *
	 * @param array $oauth options specific to OAuth 1.0 or 1.0a
	 * @param array $accessToken the variable to receive the access token
	 *
	 * @return bool true if the access token has been successfully obtained, false otherwise
	 *
	 * @throws \eureka2\OAuth\Exception\OAuthClientException if an error occurs.
	 */
	protected function requestAnOAuthAccessToken($oauth, &$accessToken) {
		$url = $this->getTokenEndpoint();
		$options = [
			'resource' => 'OAuth access token',
		];
		$method = strtoupper($this->strategy->getTokenRequestMethod());
		switch ($method) {
			case 'GET':
				break;
			case 'POST':
				$options['post_data_in_uri'] = true;
				break;
			default:
				throw new OAuthClientException($method . ' is not a supported method to request tokens');
		}
		if (($response = $this->sendOAuthRequest($url, $method, [], $options, $oauth)) === false) {
			return false;
		}
		if (!isset($response['oauth_token']) || !isset($response['oauth_token_secret'])) {
			throw new OAuthClientAuthorizationException('it was not returned the access token and secret');
		}
		$accessToken = [
			'value' => $response['oauth_token'],
			'secret' => $response['oauth_token_secret'],
			'authorized' => true
		];
		if (isset($response['oauth_expires_in']) && $response['oauth_expires_in'] == 0) {
			$this->trace('Ignoring access token expiry set to 0');
			$this->setAccessTokenExpiry('');
		} elseif (isset($response['oauth_expires_in'])) {
			$expires = $response['oauth_expires_in'];
			if (strval($expires) !== strval(intval($expires)) || $expires <= 0) {
				throw new OAuthClientException('OAuth provider did not return a supported type of access token expiry time');
			}
			$this->setAccessTokenExpiry(gmstrftime('%Y-%m-%d %H:%M:%S', $this->getResponseTime() + $expires));
			$this->trace('Access token expiry: ' . $this->getAccessTokenExpiry() . ' UTC');
			$accessToken['expiry'] = $this->getAccessTokenExpiry();
		} else {
			$this->setAccessTokenExpiry('');
		}
		if (isset($response['oauth_session_handle'])) {
			$accessToken['refresh'] = $response['oauth_session_handle'];
			$this->trace('Refresh token: ' . $accessToken['refresh']);
		}
		return $this->storage->storeAccessToken($accessToken);
	}

	/**
	 * {@inheritdoc}
	 */
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
		$twoLegged = isset($options['2legged']) && $options['2legged'];
		if (!$twoLegged && !empty($this->getAccessTokenExpiry()) && strcmp($this->getAccessTokenExpiry(), gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0) {
			if (empty($this->getRefreshToken())) {
				throw new OAuthClientException('the access token expired and no refresh token is available');
			}
			$this->trace('Refreshing the OAuth access token expired on ' . $this->getAccessTokenExpiry());
			$oauth = [
				'oauth_token' => $this->getAccessToken(),
				'oauth_session_handle' => $this->getRefreshToken()
			];
			if (!$this->requestAnOAuthAccessToken($oauth, $accessToken)) {
				return false;
			}
			if (!isset($accessToken['authorized']) || !$accessToken['authorized']) {
				throw new OAuthClientException('failed to obtain a renewed the expired access token');
			}
			$this->setAccessToken($accessToken['value']);
			$this->setAccessTokenSecret($accessToken['secret']);
			if (isset($accessToken['refresh'])) {
				$this->setRefreshToken($accessToken['refresh']);
			}
		}
		$oauth = [];
		if (!$twoLegged) {
			$oauth[!empty($this->strategy->getAccessTokenParameter()) ? $this->strategy->getAccessTokenParameter() : 'oauth_token'] = $this->getAccessToken();
		}
		return $this->sendOAuthRequest($url, $method, $parameters, $options, $oauth);
	}

	/**
	 * {@inheritdoc}
	 */
	public function checkAccessToken(&$redirectUrl) {
		$this->checkNoToken();
		$version1a = ($this->provider->getProtocol() == 'oauth' && $this->provider->getVersion() === '1.0a');
		$this->trace('Checking the OAuth token authorization state');
		if (($accessToken = $this->storage->getStoredAccessToken()) === null) {
			return false;
		}
		$redirectUrl = null;
		if (isset($accessToken['expiry'])) {
			$this->setAccessTokenExpiry($accessToken['expiry']);
		}
		if (isset($accessToken['authorized']) && isset($accessToken['value'])) {
			$expired = (isset($accessToken['expiry']) && strcmp($accessToken['expiry'], gmstrftime('%Y-%m-%d %H:%M:%S')) <= 0);
			if (!$accessToken['authorized'] || $expired) {
				if ($this->isDebug()) {
					if ($expired) {
						$this->trace('The OAuth token expired on ' . $accessToken['expiry'] . 'UTC');
					} else {
						$this->trace('The OAuth token is not yet authorized');
					}
				}
				if ($version1a && $this->provider->getRedirectUri() === 'oob' && strlen($this->provider->getPin())) {
					$this->trace('Checking the pin');
					$this->setAccessTokenSecret($accessToken['secret']);
					$oauth = [
						'oauth_token' => $accessToken['value'],
						'oauth_verifier' => $this->provider->getPin()
					];
					if (!$this->requestAnOAuthAccessToken($oauth, $accessToken)) {
						return false;
					}
					$this->trace('The OAuth token was authorized');
				} else {
					$this->trace('Checking the OAuth token and verifier');
					$token = $this->getRequestToken();
					$verifier = $this->getRequestVerifier();
					if (!isset($token) || ($version1a && !isset($verifier))) {
						$denied = $this->getRequestDenied();
						if (isset($denied) && $denied === $accessToken['value']) {
							$this->trace('The authorization request was denied');
							throw new OAuthClientAuthorizationException('the request was denied');
						} else {
							$this->trace('Reset the OAuth token state because token and verifier are not both set');
							$accessToken = [];
						}
					} elseif ($token !== $accessToken['value']) {
						$this->trace('Reset the OAuth token state because token does not match what as previously retrieved');
						$accessToken = [];
					} else {
						$this->setAccessTokenSecret($accessToken['secret']);
						$oauth = [
							'oauth_token' => $token,
						];
						if ($version1a) {
							$oauth['oauth_verifier'] = $verifier;
						}
						if (!$this->requestAnOAuthAccessToken($oauth, $accessToken)) {
							return false;
						}
						$this->trace('The OAuth token was authorized');
					}
				}
			} else {
				$this->trace('The OAuth token was already authorized');
			}
			if (isset($accessToken['authorized']) && $accessToken['authorized']) {
				$this->setAccessToken($accessToken['value']);
				$this->setAccessTokenSecret($accessToken['secret']);
				if (isset($accessToken['refresh'])) {
					$this->setRefreshToken($accessToken['refresh']);
				}
				return true;
			}
		} else {
			$this->trace('The OAuth access token is not set');
			$accessToken = [];
		}
		if (!isset($accessToken['authorized'])) {
			$this->trace('Requesting the unauthorized OAuth token');
			$url = $this->provider->getRequestTokenEndpoint();
			$url = str_replace('{SCOPE}', urlencode($this->strategy->getScope()), $url);
			$oauth = [
				'oauth_callback' => $this->provider->getRedirectUri(),
			];
			$options = [
				'resource' => 'OAuth request token',
				'fail_on_access_error' => true
			];
			$method = strtoupper($this->strategy->getTokenRequestMethod());
			switch ($method) {
				case 'GET':
					break;
				case 'POST':
					$options['post_data_in_uri'] = true;
					break;
				default:
					throw new OAuthClientException($method . ' is not a supported method to request tokens');
			}
			if (($response = $this->sendOAuthRequest($url, $method, [], $options, $oauth)) === false) {
				return false;
			}
			if (!isset($response['oauth_token']) || !isset($response['oauth_token_secret'])) {
				throw new OAuthClientAuthorizationException('it was not returned the requested token');
			}
			$accessToken = [
				'value' => $response['oauth_token'],
				'secret' => $response['oauth_token_secret'],
				'authorized' => false
			];
			if (isset($response['login_url'])) {
				$accessToken['login_url'] = $response['login_url'];
			}
			if (!$this->storage->storeAccessToken($accessToken)) {
				return false;
			}
		}
		$url = $this->provider->getAuthorizationEndpoint();
		switch ($url) {
			case 'automatic':
				if (!isset($accessToken['login_url'])) {
					throw new OAuthClientException('The request token response did not automatically the login dialog URL as expected');
				}
				$this->trace('Dialog URL obtained automatically from the request token response: ' . $url);
				$url = $accessToken['login_url'];
				break;
			case '2legged':
				$this->trace('Obtaining 2 legged access token');
				$this->setAccessTokenSecret($accessToken['secret']);
				$oauth = [
					'oauth_token' => $accessToken['value'],
				];
				if (!$this->requestAnOAuthAccessToken($oauth, $accessToken)) {
					return false;
				}
				$this->trace('The OAuth token was authorized');
				return true;
			default:
				$url .= (strpos($url, '?') === false ? '?' : '&') . 'oauth_token=' . $accessToken['value'];
		}
		if (!$version1a) {
			$url .= '&oauth_callback=' . urlencode($this->provider->getRedirectUri());
		}
		$redirectUrl = $url;
		return true;
	}

	/**
	 * Builds the base string for the signature of request data.
	 *
	 * @return string the base string
	 */
	protected function buildBaseString($url, $method, $values) {
		$uri = strtok($url, '?');
		$baseString = $method . '&' . str_replace(['%7E', '+'], ['~', ' '], rawurlencode($uri)) . '&';
		$signValues = $values;
		$parts = parse_url($url);
		if (isset($parts['query'])) {
			parse_str($parts['query'], $query);
			foreach ($query as $parameter => $value) {
				$signValues[$parameter] = $value;
			}
		}
		ksort($signValues);
		$baseString .= str_replace(['%7E', '+'], ['~', ' '], rawurlencode(http_build_query($signValues)));
		return $baseString;
	}

	/**
	 * {@inheritdoc}
	 */
	protected function signRequestData($url, $method, $parameters, $oauth, $requestContentType, $hasFiles, $postDataInUri) {
		$values = [
			'oauth_consumer_key' => $this->provider->getClientId(),
			'oauth_nonce' => md5(uniqid(''.rand(), true)),
			'oauth_signature_method' => $this->strategy->getSignatureMethod(),
			'oauth_timestamp' => (string)time(),
			'oauth_version' => '1.0',
		];
		if ($hasFiles) {
			$valueParameters = [];
		} else {
			if (($this->strategy->isParametersInUrl() || $method !== 'POST') && $requestContentType === 'application/x-www-form-urlencoded' && count($parameters) > 0) {
				$url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($parameters);
				$parameters = [];
			}
			$valueParameters = (($requestContentType !== 'application/x-www-form-urlencoded') ? [] : $parameters);
		}
		$headerValues = ($method === 'GET' ? array_merge($values, $oauth, $valueParameters) : array_merge($values, $oauth));
		$values = array_merge($values, $oauth, $valueParameters);
		$key = implode('&', [
			str_replace(['%7E', '+'], ['~', ' '], rawurlencode($this->provider->getClientSecret())),
			str_replace(['%7E', '+'], ['~', ' '], rawurlencode($this->getAccessTokenSecret()))
		]);
		switch ($this->strategy->getSignatureMethod()) {
			case 'PLAINTEXT':
				$headerValues['oauth_signature'] = $values['oauth_signature'] = $key;
				break;
			case 'HMAC-SHA1':
				$baseString = $this->buildBaseString($url, $method, $values);
				$signature = hash_hmac('sha1', $baseString, $key, true);
				$headerValues['oauth_signature'] = $values['oauth_signature'] = base64_encode($signature);
				break;
			case 'RSA-SHA1':
				if (empty($this->strategy->getSignatureCertificateFile())) {
					throw new OAuthClientException(
						sprintf(
							"the signature certificate file is required for the '%s' signature method.",
							$this->strategy->getSignatureMethod()
						)
					);
				}
				$privateKey = openssl_pkey_get_private('file://' . $this->strategy->getSignatureCertificateFile()); 
				$baseString = $this->buildBaseString($url, $method, $values);
				openssl_sign($baseString, $signature, $privateKey);
				openssl_free_key($privateKey);
				$headerValues['oauth_signature'] = $values['oauth_signature'] = base64_encode($signature);
				break;
			default:
				throw new OAuthClientException(
					sprintf(
						'%s signature method is not supported',
						$this->strategy->getSignatureMethod()
					)
				);
		}
		if ($this->strategy->isAuthorizationInHeader()) {
			$authorization = 'OAuth ';
			if (!empty($headerValues)) {
				ksort($headerValues);
				foreach($headerValues as $header => &$values) {
					$values = '"'.$values.'"';
				}
				$authorization .= str_replace('%22', '"', http_build_query($headerValues, '', ', '));
			}
			$postData = $parameters;
		} else {
			$authorization = '';
			if ($method !== 'POST' || $postDataInUri) {
				$url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($values);
				$postData = [];
			} else {
				$postData = $values;
			}
		}
		return [$url, $authorization, $postData];
	}

}

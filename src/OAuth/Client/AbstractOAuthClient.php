<?php

namespace eureka2\OAuth\Client;

use Symfony\Component\HttpClient\HttpClient;
use eureka2\OAuth\Request\OAuthRequest;
use eureka2\OAuth\Response\ResourceOwner;
use eureka2\OAuth\Exception\{OAuthClientException, OAuthClientAccessTokenException};
use eureka2\OAuth\Provider\{OAuthProvider, OAuthBuiltinProviders};
use eureka2\OAuth\Storage\TokenStorageFactory;

/**
 *
 * Base class for all Oauth clients :
 *
 * 	1)	Implement the OAuth protocol to retrieve a token from a server to
 * 		authorize the access to an API on behalf of the current user.
 *
 * 	2)	Perform calls to a Web services API using a token previously
 * 		obtained using this class or a token provided some other way by the
 * 	 	Web services provider.
 *
 * 	 	Regardless of your purposes, you always need to start calling
 * 	 	the class initialize function after initializing setup variables.
 * 		After you are done with the class,
 * 	 	always call the finalize function at the end.
 *
 * 	 	This class supports either OAuth protocol versions 1.0, 1.0a, 2.0 and OpenID.
 * 		It abstracts the differences between these protocol versions,
 * 		so the class usage is the same independently of the OAuth version of the server.
 *
 * 		The OAuthBuiltinProviders class provides built-in support to several popular OAuth providers,
 * 		so you do not have to manually configure all the details to access those providers.
 *
 * 		If you need to access one provider that is not yet directly
 * 		supported by the OAuthBuiltinProviders class,
 * 		you need to configure it explicitly setting the variables: 
 * 			protocol,
 * 			version,
 * 			url_parameters,
 * 			authorization_header,
 * 			request_token_endpoint,
 * 			authorization_endpoint,
 * 			reauthentication_parameter,
 * 			pin_dialog_url,
 * 			offline_access_parameter,
 * 			append_state_to_redirect_uri,
 * 			token_endpoint.
 * 			scope,
 * 			oauth_username,
 * 			oauth_password,
 * 			grant_type and
 * 			token_endpoint.
 *
 * 		Before proceeding to the actual OAuth authorization process, you
 * 		need to have registered your application with the OAuth provider.
 * 		The registration provides you values to set the variables
 * 		client_id and client_secret.
 * 		Some servers also provide an additional value to set the api_key variable.
 * 		You also need to set the variable redirect_uri before calling the authenticate function
 * 		to make the class perform the necessary interactions with the OAuth server.
 *
 * 		The OAuth protocol involves multiple steps that include redirection
 * 		to the OAuth server. There it asks permission to the current user to
 * 		grant your application access to APIs on his/her behalf.
 *
 * 		When there is a redirection, the class will set the exit variable,
 * 		then your script should exit immediately without outputting anything.
 *
 * 		When the OAuth access token is successfully obtained, the following
 * 		variables are set by the class with the obtained values:
 * 			accessToken,
 * 			accessTokenSecret,
 * 			accessTokenExpiry,
 * 			accessTokenType.
 *
 * 		You may want to store these values to use them later when calling the server APIs.
 * 		Once you get the access token, you can call the server APIs using the callAPI function.
 * 		Check the access_token_error variable to determine if there was an error when trying to to call the API.
 *
 * 		If for some reason the user has revoked the access to your
 * 		application, you need to ask the user to authorize your application again.
 * 		First you may need to call the function resetAccessToken to reset the value of
 * 		the access token that may be cached in session variables.
 *
 */
abstract class AbstractOAuthClient implements OAuthClientInterface {
	
	protected $oauthUserAgent = 'OAuth Client (https://www.eureka-soft.fr)';

	/**
	 *
	 * 	@var bool $debug
	 * 	Control whether debug output is enabled
	 * 	Set this variable to true if you
	 * 	need to check what is going on during calls to the class. When
	 * 	enabled, the debug output goes either to the variable
	 * 	@link debug_output and the PHP error log.
	 *
	 */
	protected $debug = false;

	/**
	 *
	 * 	@var bool $debugHttp
	 * 	Control whether the dialog with the remote Web server
	 * 	should also be logged.
	 * 	Set this variable to true if you
	 * 	want to inspect the data exchange with the OAuth server.
	 *
	 */
	protected $debugHttp = false;

	/**
	 *
	 * 	@var string $logFileName
	 * 	Name of the file to store log messages
	 * 	Set this variable to the path of a file to which log messages
	 * 	will be appended instead of sending to PHP error log when the
	 * 	@link debug variable is set to true.
	 *
	 */
	protected $logFileName = '';

	/**
	 *
	 * 	@var bool $exit
	 * 	Determine if the current script should be exited.
	 * 	Check this variable after calling the
	 * 	authenticate function and exit your script
	 * 	immediately if the variable is set to true.
	 *
	 */
	protected $exit = false;

	/**
	 *
	 * 	@var string $debugOutput
	 * 	Capture the debug output generated by the class
	 * 	Inspect this variable if you need to see what happened during
	 * 	the class function calls.
	 *
	 */
	protected $debugOutput = '';

	/**
	 *
	 * 	@var string $debugPrefix
	 * 	Mark the lines of the debug output to identify actions
	 * 	performed by this class.
	 * 	Change this variable if you prefer the debug output lines to
	 * 	be prefixed with a different text.
	 *
	 */
	protected $debugPrefix = 'OAuth client: ';

	/**
	 *
	 * 	@var string $accessToken
	 * 	Access token obtained from the OAuth server
	 *
	 * 	Check this variable to get the obtained access token upon
	 * 	successful OAuth authorization.
	 *
	 */
	protected $accessToken = '';

	/**
	 *
	 * 	@var string $accessTokenSecret
	 * 	Access token secret obtained from the OAuth server
	 *
	 * 	If the OAuth protocol version is 1.0 or 1.0a, check this
	 * 	variable to get the obtained access token secret upon successful
	 * 	OAuth authorization.
	 *
	 */
	protected $accessTokenSecret = '';

	/**
	 *
	 * 	@var string $accessTokenExpiry
	 * 	Timestamp of the expiry of the access token obtained from
	 * 	the OAuth server.
	 *
	 * 	Check this variable to get the obtained access token expiry
	 * 	time upon successful OAuth authorization. If this variable is
	 * 	empty, that means no expiry time was set.
	 *
	 */
	protected $accessTokenExpiry = '';

	/**
	 *
	 * 	@var string $accessTokenType
	 * 	Type of access token obtained from the OAuth server.
	 *
	 * 	Check this variable to get the obtained access token type
	 * 	upon successful OAuth authorization.
	 *
	 */
	protected $accessTokenType = '';

	/**
	 *
	 * 	@var array $accessTokenResponse
	 * 	The original response for the access token request
	 *
	 * 	Check this variable if the OAuth server returns custom
	 * 	parameters in the request to obtain the access token.
	 *
	 */
	protected $accessTokenResponse;

	/**
	 *
	 * 	@var string $refreshToken
	 * 	Refresh token obtained from the OAuth server
	 *
	 * 	Check this variable to get the obtained refresh token upon
	 * 	successful OAuth authorization.
	 *
	 */
	protected $refreshToken = '';

	/**
	 *
	 * 	@var object $idToken
	 * 	The id_token value from OAuth servers compatible with OpenID Connect.
	 *
	 * 	Check this variable if the OAuth server returns id_token values.
	 *
	 */
	protected $idToken = null;

	/**
	 *
	 * 	@var integer $responseStatus
	 * 	HTTP response status returned by the server when calling an  API
	 *
	 * 	Check this variable after calling the callAPI function if the API calls and you
	 * 	need to process the error depending the response status.
	 * 	200 means no error. 
	 * 	0 means the server response was not retrieved.
	 *
	 */
	protected $responseStatus = 0;

	/**
	 *
	 * 	@var array $responseHeaders
	 * 	HTTP response headers returned by the server when calling an API
	 *
	 * 	Check this variable after calling the
	 * 	callAPI function if the API calls and you
	 * 	need to process the error depending the response headers.
	 *
	 */
	protected $responseHeaders = [];

	/**
	 *
	 * 	@var string $responseBody
	 * 	HTTP response body returned by the server when calling an API
	 *
	 * 	Check this variable after calling the
	 * 	callAPI function if the API calls and you
	 * 	need to process the error depending the response headers.
	 *
	 */
	protected $responseBody = '';

	protected $responseTime = 0;

	/**
	 * OAuth Client Strategy object
	 *
	 * @var \eureka2\OAuth\Client\OAuthClientStrategy $strategy
	 */
	protected $strategy = null;

	/**
	 * OAuth Provider object
	 *
	 * @var \eureka2\OAuth\Provider\OAuthProvider $provider
	 */
	protected $provider = null;

	/**
	 * Token Storage object
	 *
	 * @var \eureka2\OAuth\Storage\TokenStorageInterface $storage
	 */
	protected $storage = null;

	public function __construct($provider = "") {
		$this->strategy = new OAuthClientStrategy();
		$this->provider = new OAuthProvider($provider);
	}

	protected function isDebug() {
		return $this->debug;
	}

	protected function isDebugHttp() {
		return $this->debugHttp;
	}

	/**
	 * @inheritdoc
	 */
	public function shouldExit() {
		return $this->exit;
	}

	/**
	 * @inheritdoc
	 */
	public function getAccessToken() {
		return $this->accessToken;
	}

	protected function getAccessTokenSecret() {
		return $this->accessTokenSecret;
	}

	protected function getAccessTokenExpiry() {
		return $this->accessTokenExpiry;
	}

	protected function getAccessTokenType() {
		return $this->accessTokenType;
	}

	protected function getAccessTokenResponse() {
		return $this->accessTokenResponse;
	}

	/**
	 * @inheritdoc
	 */
	public function getRefreshToken() {
		return $this->refreshToken;
	}

	/**
	 * @inheritdoc
	 */
	public function getIdToken() {
		return $this->idToken;
	}

	protected function getResponseStatus() {
		return $this->responseStatus;
	}

	protected function getResponseHeaders() {
		return $this->responseHeaders;
	}

	protected function getResponseHeader($header) {
		if (!isset($this->responseHeaders[$header])) {
			return null;
		}
		$responseHeader = $this->responseHeaders[$header];
		if (is_array($responseHeader) && count($responseHeader) == 1) {
			return $responseHeader[0];
		}
		return $responseHeader;
	}

	protected function getResponseBody() {
		return $this->responseBody;
	}

	protected function getOauthUserAgent() {
		return $this->oauthUserAgent;
	}

	protected function getResponseTime() {
		return $this->responseTime;
	}

	/**
	 * @inheritdoc
	 */
	public function getProvider() {
		return $this->provider;
	}

	public function setDebug($debug) {
		$this->debug = $debug;
		return $this;
	}

	public function setDebugHttp($debugHttp) {
		$this->debugHttp = $debugHttp;
		return $this;
	}

	protected function setExit($exit) {
		$this->exit = $exit;
		return $this;
	}

	public function setRedirectUri($redirect_uri) {
		$this->provider->setRedirectUri($redirect_uri);
		return $this;
	}

	public function setClientId($client_id) {
		$this->provider->setClientId($client_id);
		return $this;
	}

	public function setClientSecret($client_secret) {
		$this->provider->setClientSecret($client_secret);
		return $this;
	}

	public function setAccessToken($accessToken) {
		$this->accessToken = $accessToken;
		return $this;
	}

	public function setAccessTokenSecret($accessTokenSecret) {
		$this->accessTokenSecret = $accessTokenSecret;
		return $this;
	}

	protected function setAccessTokenExpiry($accessTokenExpiry) {
		$this->accessTokenExpiry = $accessTokenExpiry;
		return $this;
	}

	protected function setAccessTokenType($accessTokenType) {
		$this->accessTokenType = $accessTokenType;
		return $this;
	}

	protected function setAccessTokenResponse($accessTokenResponse) {
		$this->accessTokenResponse = $accessTokenResponse;
		return $this;
	}

	protected function setRefreshToken($refreshToken) {
		$this->refreshToken = $refreshToken;
		return $this;
	}

	protected function setIdToken($idToken) {
		$this->idToken = $idToken;
		return $this;
	}

	protected function setResponseStatus($responseStatus) {
		$this->responseStatus = $responseStatus;
		return $this;
	}

	protected function setResponseHeaders($responseHeaders) {
		$this->responseHeaders = $responseHeaders;
		return $this;
	}

	protected function setResponseBody($responseBody) {
		$this->responseBody = $responseBody;
		return $this;
	}

	protected function setOauthUserAgent($oauthUserAgent) {
		$this->oauthUserAgent = $oauthUserAgent;
		return $this;
	}

	protected function setResponseTime($responseTime) {
		$this->responseTime = $responseTime;
		return $this;
	}

	public function trace($message) {
		if ($this->isDebug()) {
			$message = $this->debugPrefix . $message;
			$this->debugOutput .= $message . "\n";
			if (!empty($this->logFileName)) {
				error_log($message . "\n", 3, $this->logFileName);
			} else {
				error_log($message);
			}
		}
		return true;
	}

	protected function getAuthorizationEndpoint($redirectUri = '', $state = '', $nonce = '') {
		$url = (($this->strategy->isOfflineAccess() && !empty($this->strategy->getOfflineAccessParameter()))
			? $this->provider->getAuthorizationEndpoint() . '&' . $this->strategy->getOfflineAccessParameter()
			: (($redirectUri === 'oob' && !empty($this->provider->getPinDialogUrl()))
				? $this->provider->getPinDialogUrl()
				: ($this->strategy->shouldReauthenticate()
					? $this->provider->getAuthorizationEndpoint() . '&' . $this->strategy->getReauthenticationParameter()
					: $this->provider->getAuthorizationEndpoint())));
		if (empty($url)) {
			throw new OAuthClientException(
				sprintf(
					'the authorization endpoint %s is not defined for this provider',
					($this->strategy->isOfflineAccess() ? 'for offline access ' : ($this->strategy->shouldReauthenticate() ? 'for reautentication' : ''))
				)
			);
		}
		$scope = $this->strategy->getScope();
		if ($this->strategy->isOfflineAccess() && empty($this->strategy->getOfflineAccessParameter())) {
			$sep = strpos($scope, ',') === false ? ' ' : ',';
			$scope .= $sep . 'offline_access';
		}
		$url = str_replace(
				['{NONCE}',         '{REDIRECT_URI}',        '{STATE}',         '{CLIENT_ID}',                             '{API_KEY}',                             '{SCOPE}',               '{REALM}'],
				[urlencode($nonce), urlencode($redirectUri), urlencode($state), urlencode($this->provider->getClientId()), urlencode($this->provider->getApiKey()), urlencode(trim($scope)), urlencode($this->provider->getRealm())],
				$url);
		return $url;
	}

	protected function getTokenEndpoint() {
		return str_replace('{API_KEY}', $this->provider->getApiKey(), $this->provider->getTokenEndpoint());
	}

	protected function getRevocationEndpoint($token) {
		$endPoint = $this->provider->getRevocationEndpoint();
		if (empty($endPoint)) {
			$endPoint = $this->provider->getEndSessionEndpoint();
		}
		return str_replace('{TOKEN}', $token, $endPoint);
	}

	protected function getRequestState() {
		if (filter_has_var(INPUT_GET, 'error')) {
			$this->trace('it was returned the request state error ' . filter_input(INPUT_GET, 'error'));
			return false;
		}
		$check = (!empty($this->strategy->getAppendStateToRedirectUri()) ? $this->strategy->getAppendStateToRedirectUri() : 'state');
		$state = filter_input(INPUT_GET, $check);
		return $state;
	}

	protected function getRequestCode() {
		return filter_input(INPUT_GET, 'code');
	}

	protected function getRequestError() {
		return filter_input(INPUT_GET, 'error');
	}

	protected function getRequestDenied() {
		return filter_input(INPUT_GET, 'denied');
	}

	protected function getRequestToken() {
		return filter_input(INPUT_GET, 'oauth_token');
	}

	protected function getRequestVerifier() {
		return filter_input(INPUT_GET, 'oauth_verifier');
	}

	protected function retrieveRedirectURI() {
		if (!empty($this->provider->getRedirectUri())) {
			$redirectUri = $this->provider->getRedirectUri();
		} else {
			$redirectUri = $this->makeUriFromGlobals();
		}
		return $redirectUri;
	}

	/**
	 * 	Redirect the user browser to a given page.
	 *
	 * 	This function is meant to be only be called from inside the
	 * 	class. By default it issues HTTP 302 response status and sets the
	 * 	redirection location to a given URL. Sub-classes may override this
	 * 	function to implement a different way to redirect the user
	 * 	browser.
	 *
	 * 	@param string $url the full URL of the page to redirect.
	 *
	 */
	protected function redirect($url) {
		header('HTTP/1.0 302 OAuth Redirection');
		header('Location: ' . $url);
	}

	protected function sign(&$url, $method, $parameters, $oauth, $requestContentType, $hasFiles, $postValuesInUri, &$authorization, &$postValues) {
		throw new OAuthClientException(
			sprintf(
				'the sign method is not available for the protocol %s %s',
				$this->provider->getProtocol(),
				$this->provider->getVersion()
			)
		);
	}

	protected function sendHttpRequest($oauthRequest, $options = []) {
		try {
			$http = HttpClient::create(
				['headers' => [
					'User-Agent' => $this->oauthUserAgent,
				],
				'max_redirects' => $options['max_redirects'] ?? 0
			]);
			$response = $http->request(
				$oauthRequest->getMethod(),
				$oauthRequest->getUrl(),
				[
					'headers' => $oauthRequest->getHeaders(),
					'body' => $oauthRequest->getBody()
				]
			);
			$this->setResponseStatus($response->getStatusCode());
			$this->setResponseHeaders($response->getHeaders());
			$this->setResponseBody($response->getContent());
		} catch (\Exception $e) {
			throw new OAuthClientException(
				sprintf(
					"error while running the HTTP request %s %s : %s",
					$oauthRequest->getMethod(),
					$oauthRequest->getUrl(),
					$e->getMessage()
				)
			);
		}
	}

	protected function prepareOAuthRequest($url, $method, $parameters, $options, $oauth = null) {
		$postFiles = [];
		$method = strtoupper($method);
		$authorization = '';
		$requestContentType = (isset($options['request_content_type']) ? strtolower(trim(strtok($options['request_content_type'], ';'))) : (($method === 'POST' || isset($oauth)) ? 'application/x-www-form-urlencoded' : ''));
		$files = $options['files'] ?? [];
		if (count($files) > 0) {
			foreach ($files as $name => $value) {
				if (!isset($parameters[$name])) {
					throw new OAuthClientException(
						sprintf(
							'it was not specified a file parameter named %s',
							$name
						)
					);
				}
				unset($parameters[$name]);
			}
			if ($method !== 'POST') {
				$this->trace('For uploading files the method should be POST not ' . $method);
				$method = 'POST';
			}
			if ($requestContentType !== 'multipart/form-data') {
				if (isset($options['request_content_type'])) {
					throw new OAuthClientException('the request content type for uploading files should be multipart/form-data');
				}
				$requestContentType = 'multipart/form-data';
			}
			$postFiles = $files;
		}
		if (isset($oauth)) {
			if (!$this->sign($url, $method, $parameters, $oauth, $requestContentType, count($files) !== 0, isset($options['post_values_in_uri']) && $options['post_values_in_uri'], $authorization, $post_values)) {
				return false;
			}
		} else {
			$postValues = $parameters;
			if (count($parameters)) {
				switch ($requestContentType) {
					case 'application/x-www-form-urlencoded':
					case 'multipart/form-data':
					case 'application/json':
					case 'application/javascript':
						break;
					default:
						$url .= (strpos($url, '?') === false ? '?' : '&') . http_build_query($parameters);
				}
			}
		}
		if (empty($authorization) && !strcasecmp($this->getAccessTokenType(), 'Bearer')) {
			$authorization = 'Bearer ' . $this->getAccessToken();
		}
		$requestHeaders = $options['headers'] ?? [];
		$requestBody = null;
		switch ($requestContentType) {
			case 'application/x-www-form-urlencoded':
				if (isset($options['body'])) {
					throw new OAuthClientException('the request body is defined automatically from the parameters');
				}
				$requestHeaders['Content-Type'] = $requestContentType;
				$requestBody = $postValues;
				break;
			case 'multipart/form-data':
				if (isset($options['body'])) {
					throw new OAuthClientException('the request body is defined automatically from the parameters');
				}
				$requestHeaders['Content-Type'] = $requestContentType;
				$requestBody = array_merge($postFiles, $postValues);
				break;
			case 'application/json':
			case 'application/javascript':
				$requestHeaders['Content-Type'] = $requestContentType;
				$requestBody = $options['body'] ?? $parameters;
				break;
			default:
				if (!isset($options['body'])) {
					if (isset($options['request_content_type'])) {
						throw new OAuthClientException('it was not specified the body value of the of the API call request');
					}
					break;
				}
				$requestHeaders['Content-Type'] = $requestContentType;
				$requestBody = $options['body'];
				break;
		}
		$requestHeaders['Accept'] = $options['accept'] ?? '*/**';
		$requestHeaders['Accept-Language'] = $options['accept_language'] ?? '*';
		switch ($authentication = (isset($options['authentication']) ? strtolower($options['authentication']) : '')) {
			case 'basic':
				$requestHeaders['Authorization'] = 'Basic ' . base64_encode($this->provider->getClientId() . ':' . ($this->strategy->getTokenWithApiKey() ? $this->provider->getApiKey() : $this->provider->getClientSecret()));
				break;
			case '':
				if (!empty($authorization)) {
					$requestHeaders['Authorization'] = $authorization;
				}
				break;
			case 'none':
				break;
			default:
				throw new OAuthClientException($authentication . ' is not a supported authentication mechanism to retrieve an access token');
		}
		return new OAuthRequest($url, $method, $requestHeaders, $requestBody);
	}

	protected function sendOAuthRequest($url, $method, $parameters, $options, $oauth = null) {
		$this->setResponseStatus(0);
		$this->trace('Accessing the ' . $options['resource'] . ' at ' . $url);
		if (($request = $this->prepareOAuthRequest($url, $method, $parameters, $options, $oauth)) === false) {
			return false;
		}
		$this->sendHttpRequest($request);
		if ($this->getResponseStatus() < 200 || $this->getResponseStatus() >= 300) {
			if (isset($options['fail_on_access_error']) && $options['fail_on_access_error']) {
				$reason = '';
				if ($this->getResponseStatus() == 400) {
					$body = $this->convertResponseBody($options);
					if (isset($body['error'])) {
						$reason .= $body['error'];
					}
					if (isset($body['error_description'])) {
						$reason .= '(' . $body['error_description'] . ')';
					}
				}
				throw new OAuthClientAccessTokenException(
					sprintf(
						'it was not possible to access the %s: it was returned an unexpected response status %d %s',
						$options['resource'],
						$this->getResponseStatus(),
						$reason
					)
				);
			}
		}
		$this->setResponseTime((isset($this->responseHeaders['date']) ? strtotime(is_array($this->responseHeaders['date']) ? $this->responseHeaders['date'][0] : $this->responseHeaders['date']) : time()));
		return $this->convertResponseBody($options);
	}

	protected function convertResponseBody($options) {
		$data = $this->getResponseBody();
		$contentType = (isset($options['response_content_type']) ? $options['response_content_type'] : ($this->getResponseHeader('content-type') !== null ? strtolower(trim(strtok($this->getResponseHeader('content-type'), ';'))) : 'unspecified'));
		$contentType = preg_replace('/^(.+\\/).+\\+(.+)$/', '\\1\\2', $contentType);
		$response = null;
		switch ($contentType) {
			case 'text/javascript':
			case 'application/json':
			case 'application/javascript':
				$object = json_decode($data, isset($options['convert_json_to_array']) && $options['convert_json_to_array']);
				if (!isset($object)) {
					throw new OAuthClientException('it was not returned a valid JSON definition of the ' . $options['resource'] . ' values');
				}
				$response = $object;
				break;
			case 'application/x-json-access-token':
				$object = json_decode($data);
				if (gettype($object) !== 'object') {
					throw new OAuthClientException('the access token response is not in the JSON format');
				}
				$response = ['response' => $object];
				if (isset($object->access_token) && isset($object->access_token->token)) {
					$response['access_token'] = $object->access_token->token;
				}
				break;
			case 'application/x-www-form-urlencoded':
			case 'text/plain':
			case 'text/html':
				parse_str($data, $response);
				break;
			case 'text/xml':
				if (isset($options['decode_xml_response'])) {
					switch (strtolower($options['decode_xml_response'])) {
						case 'simplexml':
							$this->trace('Decoding XML response with simplexml');
							try {
								$data = new \SimpleXMLElement($data);
							} catch (\Exception $exception) {
								throw new OAuthClientException('Could not parse XML response: ' . $exception->getMessage());
							}
							break;
						default:
							throw new OAuthClientException($options['decode_xml_response'] . ' is not a supported method to decode XML responses');
					}
				}
			default:
				$response = $data;
				break;
		}
		return $response ?? false;
	}

	protected function isThereAStoredAccessToken() {
		return $this->storage->getStoredAccessToken() !== null;
	}

	protected function isStoredAccessTokenValid() {
		if (!$this->isThereAStoredAccessToken()) {
			return false;
		}
		$accessToken = $this->storage->getStoredAccessToken();
		if (isset($accessToken['value']) && !empty($accessToken['value'])) {
			$this->setAccessToken($accessToken['value']);
			if (isset($accessToken['expiry'])) {
				$this->setAccessTokenExpiry($accessToken['expiry']);
				$expired = strcmp($accessToken['expiry'], gmstrftime('%Y-%m-%d %H:%M:%S')) < 0;
			} else {
				$this->setAccessTokenExpiry('');
				$expired = false;
			}
			if ($this->isDebug()) {
				if ($expired) {
					$this->trace('The OAuth access token expired on ' . $this->getAccessTokenExpiry() . ' UTC');
				} elseif (!empty($this->getAccessToken())) {
					$this->trace('The OAuth access token ' . $this->getAccessToken() . ' is valid');
					if (!empty($this->getAccessTokenExpiry())) {
						$this->trace('The OAuth access token expires on ' . $this->getAccessTokenExpiry());
					}
				} else {
					$this->trace('The OAuth access token value was not retrieved before.');
				}
			}
			if (isset($accessToken['type'])) {
				$this->setAccessTokenType($accessToken['type']);
				if (!empty($this->getAccessTokenType()) && !$expired && $this->isDebug()) {
					$this->trace('The OAuth access token is of type ' . $this->getAccessTokenType());
				}
			} else {
				$this->setAccessTokenType($this->strategy->getDefaultAccessTokenType());
				if (!empty($this->getAccessTokenType()) && !$expired && $this->isDebug()) {
					$this->trace('Assumed the default for OAuth access token type which is ' . $this->getAccessTokenType());
				}
			}
			if (isset($accessToken['secret']) && !empty($accessToken['secret'])) {
				$this->setAccessTokenSecret($accessToken['secret']);
				if ($this->isDebug() && !$expired && !empty($this->getAccessTokenSecret())) {
					$this->trace('The OAuth access token secret is ' . $this->getAccessTokenSecret());
				}
			}
			if (isset($accessToken['refresh'])) {
				$this->setRefreshToken($accessToken['refresh']);
			} else {
				$this->setRefreshToken('');
			}
			if (isset($accessToken['id_token']) && !empty($accessToken['id_token'])) {
				$this->setIdToken($accessToken['id_token']);
			} else {
				$this->setIdToken(null);
			}
			$this->setAccessTokenResponse((($this->strategy->shouldStoreAccessTokenResponse() && isset($accessToken['response'])) ? $accessToken['response'] : null));
			return true;
		}
		return false;
	}

	/**
	 * @inheritdoc
	 */
	abstract public function callAPI($url, $method, $parameters, $options);

	/**
	 * @inheritdoc
	 */
	public function getResourceOwner($endpoint = null) {
		$endpoint = $endpoint ?? $this->provider->getUserinfoEndpoint();
		$user = empty($endpoint)
			? []
			: $this->callAPI(
				$endpoint,
				'GET', [], [
					'convert_json_to_array' => true,
					'fail_on_access_error' => true
				]
			);
		$userId = $this->storage->getStoredUser();
		if (empty($userId) &&!empty($this->provider->getUserIdField())) {
			$field = $this->provider->getUserIdField();
			if (isset($user[$field])) {
				$userId = $user[$field];
			}
		}
		return new ResourceOwner($userId, $user);
	}

	/**
	 * @inheritdoc
	 */
	public function fetchResourceOwner($options) {
		$user = null;
		if ($this->initialize($options)) {
			if ($this->authenticate()) {
				if (!empty($this->getAccessToken())) {
					$user = $this->getResourceOwner();
				}
			}
			$this->finalize();
		}
		if ($this->shouldExit()) {
			exit;
		}
		return $user;
	}

	protected function checkTokenBeforeCall($options) {
		$version = intval($this->provider->getVersion());
		$twoLegged = ($this->provider->getProtocol() == 'oauth' && $version === 1 && isset($options['2legged']) && $options['2legged']);
		if (empty($this->getAccessToken()) && !$twoLegged) {
			if (!$this->isThereAStoredAccessToken()) {
				return false;
			}
			if (!$this->isStoredAccessTokenValid()) {
				throw new OAuthClientException('the access token is not set to a valid value');
			}
		}
		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function initialize($options = []) {
		$this->storage = TokenStorageFactory::create($this, $options['storage'] ?? [ 'type' => 'session' ]);
		if (strlen($this->provider->getName()) === 0) {
			return true;
		}
		$configuration = [];
		$builtin = OAuthBuiltinProviders::PROVIDERS[$this->provider->getName()] ?? [];
		if (isset($builtin['endpoints']) && isset($builtin['endpoints']['discovery_endpoint'])) {
			$configuration = array_merge($configuration, $this->discover($builtin['endpoints']['discovery_endpoint']));
		}
		if (isset($builtin['protocol'])) {
			$configuration = array_merge($configuration, [
				'protocol' => $builtin['protocol']['name'],
				'version' => $builtin['protocol']['version']
			]);
		}
		if (isset($builtin['endpoints'])) {
			$configuration = array_merge($configuration, $builtin['endpoints']);
		}
		if (isset($builtin['mapping'])) {
			$configuration = array_merge($configuration, $builtin['mapping']);
		}
		if (isset($options['provider']) && isset($options['provider']['endpoints']) && isset($options['provider']['endpoints']['discovery_endpoint'])) {
			$configuration = array_merge($configuration, $this->discover($options['provider']['endpoints']['discovery_endpoint']));
		}
		if (isset($options['provider']) && isset($options['provider']['protocol'])) {
			$configuration = array_merge($configuration, [
				'protocol' => $options['provider']['protocol']['name'],
				'version' => $options['provider']['protocol']['version']
			]);
		}
		if (isset($options['provider']) && isset($options['provider']['endpoints'])) {
			$configuration = array_merge($configuration, $options['provider']['endpoints']);
		}
		if (isset($options['provider']) && isset($options['provider']['mapping'])) {
			$configuration = array_merge($configuration, $options['provider']['mapping']);
		}
		$this->provider->bind($configuration);
		$this->initializeRegitrationOptions($options);
		$strategy = $builtin['strategy'];
		if (isset($options['strategy'])) {
			$strategy = array_merge($strategy, $options['strategy']);
		}
		$this->strategy->bind($strategy);
		$this->storage->initialize();
		return true;
	}

	protected function initializeRegitrationOptions($options) {
		if (isset($options['provider']) && isset($options['provider']['registration'])) {
			if (isset($options['provider']['registration']['keys'])) {
				if (isset($options['provider']['registration']['keys']['client_id'])) {
					$this->provider->setClientId($options['provider']['registration']['keys']['client_id']);
				}
				if (isset($options['provider']['registration']['keys']['client_secret'])) {
					$this->provider->setClientSecret($options['provider']['registration']['keys']['client_secret']);
				}
				if (isset($options['provider']['registration']['keys']['redirect_uri'])) {
					$this->provider->setRedirectUri($options['provider']['registration']['keys']['redirect_uri']);
				}
				if (isset($options['provider']['registration']['keys']['api_key'])) {
					$this->provider->setApiKey($options['provider']['registration']['keys']['api_key']);
				}
				if (isset($options['provider']['registration']['keys']['realm'])) {
					$this->provider->setRealm($options['provider']['registration']['keys']['realm']);
				}
				if (isset($options['provider']['registration']['keys']['pin'])) {
					$this->provider->setPin($options['provider']['registration']['keys']['pin']);
				}
			}
			if (isset($options['provider']['registration']['credentials'])) {
				if (isset($options['provider']['registration']['credentials']['oauth_username'])) {
					$this->provider->setOauthUsername($options['provider']['registration']['credentials']['oauth_username']);
				}
				if (isset($options['provider']['registration']['credentials']['oauth_password'])) {
					$this->provider->setOauthPassword($options['provider']['registration']['credentials']['oauth_password']);
				}
			}
		}
	}

	protected function discover($discoveryEndpoint) {
		throw new OAuthClientException(
			sprintf(
				'the discover method is not available for the protocol %s %s',
				$this->provider->getProtocol(),
				$this->provider->getVersion()
			)
		);
	}

	protected function checkNoToken() {
		if (!empty($this->getAccessToken()) || !empty($this->getAccessTokenSecret())) {
			$this->trace('The authenticate function should not be called again if the OAuth token was already set manually');
			throw new OAuthClientException('the OAuth token was already set');
		}
	}

	/**
	 * @inheritdoc
	 */
	public function authenticate() {
		if (!$this->checkAccessToken($redirectUrl)) {
			return false;
		}
		if (isset($redirectUrl)) {
			$this->trace('Redirecting to OAuth authorization server : ' . $redirectUrl);
			$this->redirect($redirectUrl);
			$this->setExit(true);
		}
		return true;
	}

	abstract public function checkAccessToken(&$redirectUrl);

	/**
	 * @inheritdoc
	 */
	public function resetAccessToken() {
		return $this->storage->resetAccessToken();
	}

	public function canRevokeToken() {
		$token = $this->getAccessToken();
		if (($revocationEndpoint = $this->getRevocationEndpoint($token)) === null) {
			return false;
		}
		if (empty($revocationEndpoint)) {
			return false;
		}
		$redirectUrl = null;
		if (!$this->checkAccessToken($redirectUrl) || !isset($redirectUrl)) {
			return false;
		}
		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function revokeToken($tokenTypeHint = 'access_token') {
		if (!in_array($tokenTypeHint, ['access_token', 'refresh_token'])) {
			throw new OAuthClientException(
				sprintf(
					'Revoking tokens of type %s is not supported',
					$tokenTypeHint
				)
			);
		}
		$token = $tokenTypeHint == 'access_token' ? $this->getAccessToken() : $this->getRefreshToken();
		if (empty($token)) {
			return false;
		}
		if (($revocationEndpoint = $this->getRevocationEndpoint($token)) === null) {
			return false;
		}
		if (empty($revocationEndpoint)) {
			throw new OAuthClientException('OAuth revoke token URL is not defined');
		}
		$parameters = [
			'token' => $token,
			'token_type_hint' => $tokenTypeHint
		];
		$options = [
			'resource' => 'OAuth revoke token',
			'fail_on_access_error' => true,
			'authentication' => 'basic',
			'accept' => 'application/json'
			
		];
		$this->trace('Revoking token of type ' . $tokenTypeHint . ': ' . $token);
		if ($this->sendOAuthRequest($revocationEndpoint, 'POST', $parameters, $options) === false) {
			return false;
		}
		if ($tokenTypeHint === 'access_token') {
			return $this->storage->resetAccessToken();
		}
		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function finalize() {
		$this->storage->finalize();
	}

	protected function makeUriFromGlobals() {
		$server = filter_input_array(INPUT_SERVER);
		if (isset($server['HTTP_UPGRADE_INSECURE_REQUESTS']) && ($server['HTTP_UPGRADE_INSECURE_REQUESTS'] == 1)) {
			$scheme = 'https';
		} elseif (isset($server['HTTP_X_FORWARDED_PROTO'])) {
			$scheme = $server['HTTP_X_FORWARDED_PROTO'];
		} elseif (isset($server['REQUEST_SCHEME'])) {
			$scheme = $server['REQUEST_SCHEME'];
		} elseif (isset($server['HTTPS']) && $server['HTTPS'] !== 'off') {
			$scheme = 'https';
		} else {
			$scheme = 'http';
		}
		if (isset($server['HTTP_X_FORWARDED_HOST']) && !empty($server['HTTP_X_FORWARDED_HOST'])) {
			$host = explode(':', $server['HTTP_X_FORWARDED_HOST'])[0];
		} elseif (isset($server['HTTP_HOST']) && !empty($server['HTTP_HOST'])) {
			$host = explode(':', $server['HTTP_HOST'])[0];
		} elseif (isset($server['SERVER_NAME']) && !empty($server['SERVER_NAME'])) {
			$host = $server['SERVER_NAME'];
		} else {
			$host = $server['SERVER_ADDR'];
		}
		if (isset($server['HTTP_X_FORWARDED_PORT']) && !empty($server['HTTP_X_FORWARDED_PORT'])) {
			$port = (int)$server['HTTP_X_FORWARDED_PORT'];
		} elseif (isset($server['HTTP_X_FORWARDED_HOST']) && !empty($server['HTTP_X_FORWARDED_HOST']) && strpos($server['HTTP_X_FORWARDED_HOST'], ':') !== false) {
			$port = (int)explode(':', $server['HTTP_X_FORWARDED_HOST'])[1];
		} elseif (isset($server['SERVER_PORT']) && !empty($server['SERVER_PORT'])) {
			$port = (int)$server['SERVER_PORT'];
		} elseif (isset($server['HTTP_HOST']) && !empty($server['HTTP_HOST']) && strpos($server['HTTP_HOST'], ':') !== false) {
			$port = (int)explode(':', $server['HTTP_HOST'])[1];
		} else {
			$port = $scheme === 'https' ? 443 : 80;
		}
		$port = (443 == $port) || (80 == $port) ? '' : ':' . $port;
		$requestUri = trim(strtok($server['REQUEST_URI'], '?'), '/');
		return sprintf('%s://%s%s/%s', $scheme, $host, $port, $requestUri);
	}

	/**
	 * @inheritdoc
	 */
	public function canLogOut() {
		$endPoint = $this->provider->getEndSessionEndpoint();
		if (empty($endPoint)) {
			return false;
		}
		if (!$this->isStoredAccessTokenValid()) {
			return false;
		}
		return true;
	}

	/**
	 * @inheritdoc
	 */
	public function logOut($redirect = null) {
		if (!$this->canLogOut()) {
			return false;
		}
		$endPoint = $this->provider->getEndSessionEndpoint();
		$params = [];
		$accessToken = $this->storage->getStoredAccessToken();
		$idToken = $accessToken['id_token'] ?? '';
		if (!empty($idToken)) {
			$params['id_token_hint'] = $idToken;
		}
		$state = $this->storage->getStoredState();
		if (!is_null($state)) {
			$params['state'] = $state;
		}
		if($redirect !== null){
			$params['post_logout_redirect_uri'] = $redirect;
		}
		$endPoint .= (strpos($endPoint, '?') === false ? '?' : '&') . http_build_query($params, null, '&');
		$this->redirect($endPoint);
		$this->setExit(true);
	}

}

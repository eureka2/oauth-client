<?php declare(strict_types = 1);

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Exception\OAuthClientException;

/**
 * This class holds the options of execution of the OAuth client.
 *
 * This set of options is the authentication strategy.
 */
class OAuthClientStrategy {

	const TYPES = [
		'reauthentication_parameter' => 'string',
		'offline_access' => 'boolean',
		'offline_access_parameter' => 'string',
		'append_state_to_redirect_uri' => 'string',
		'authorization_in_header' => 'boolean',
		'parameters_in_url' => 'boolean',
		'token_request_method' => 'string',
		'signature_method' => 'string',
		'signature_certificate_file' => 'string',
		'access_token_authentication' => 'string',
		'access_token_parameter' => 'string',
		'default_access_token_type' => 'string',
		'store_access_token_response' => 'boolean',
		'refresh_token_authentication' => 'string',
		'grant_type' => 'string',
		'get_token_with_api_key' => 'boolean',
		'access_token_content_type' => 'string',
		'access_token_language' => 'string',
		'scope' => 'string'
	];

	/**
	 * The parameters to add to the OAuth provider authorization endpoint URL
	 * in case of new authentication.
	 *
	 * 	@var string $reauthentication_parameter
	 *
	 */
	private $reauthentication_parameter = '';

	/**
	 * The parameter to add to the OAuth provider
	 * authorization endpoint URL when offline access is requested.
	 *
	 * 	@var string $offline_access_parameter
	 *
	 */
	private $offline_access_parameter = '';

	/**
	 * The name of the OAuth session state variable,
	 * if different from the standard name,
	 * to work around the implementation bugs of some OAuth providers.
	 *
	 * 	@var string $append_state_to_redirect_uri
	 *
	 */
	private $append_state_to_redirect_uri = '';

	/**
	 * Determines if the API call parameters should be moved to the
	 * calling URL.
	 *
	 * @var bool $parameters_in_url
	 *
	 */
	private $parameters_in_url = false;

	/**
	 * Determines if the OAuth parameters should be passed via HTTP
	 * Authorization request header.
	 *
	 * @var bool $authorization_in_header
	 *
	 */
	private $authorization_in_header = true;

	/**
	 * Define the HTTP method that should be used to request
	 * tokens from the provider.
	 *
	 * @var string $token_request_method
	 *
	 */
	private $token_request_method = 'GET';

	/**
	 * If Oauth 1.0 or 1.0a, define the method to generate the signature for API request
	 * parameters values.
	 *
	 * @var string $signature_method
	 *
	 */
	private $signature_method = 'HMAC-SHA1';

	/**
	 * If signature_method is 'RSA-SHA1', this variable must contains
	 * the full path of the file containing a PEM encoded certificate/private key
	 *
	 * @var string $signature_certificate_file
	 *
	 */
	private $signature_certificate_file = '';

	/**
	 * Permissions that your application needs to call the OAuth
	 * provider APIs
	 *
	 * @var string $scope
	 *
	 */
	private $scope = '';

	/**
	 * Specify whether it will be necessary to call the API when
	 * the user is not present and the provider supports renewing expired
	 * access tokens using refresh tokens.
	 *
	 * @var bool $offline_access
	 *
	 */
	private $offline_access = false;

	/**
	 * Specify whether it will be necessary to force the user to
	 * authenticate again even after the user has already authorized the
	 * application before.
	 *
	 * @var bool $reauthenticate
	 *
	 */
	private $reauthenticate = false;

	/**
	 * Type of access token to be assumed when the OAuth provider
	 * does not specify an access token type.
	 *
	 * @var string $default_access_token_type
	 *
	 */
	private $default_access_token_type = '';

	/**
	 * Content type to be assumed when retrieving the response to
	 * a request to retrieve the access token.
	 *
	 * @var string $access_token_content_type
	 *
	 */
	private $access_token_content_type = '';

	/**
	 * Language to be assumed when retrieving the response to
	 * a request to retrieve the access token.
	 *
	 * @var string $access_token_language
	 *
	 */
	private $access_token_language = '';

	/**
	 * Name of the access token parameter to be passed in API call
	 * requests.
	 *
	 * @var string $access_token_parameter
	 *
	 */
	private $access_token_parameter = '';

	/**
	 * Option to determine if the original response for the access
	 * token request should be stored in the
	 * accessTokenResponse variable.
	 *
	 * @var bool $store_access_token_response
	 *
	 */
	private $store_access_token_response = false;

	/**
	 * Option to determine if the requests to obtain a new access
	 * token should use authentication to pass the application client ID
	 * and secret.
	 *
	 * @var string $access_token_authentication
	 *
	 */
	private $access_token_authentication = '';

	/**
	 * Option to determine if the requests to refresh an expired
	 * access token should use authentication to pass the application
	 * client ID and secret.
	 *
	 * @var string $refresh_token_authentication
	 *
	 */
	private $refresh_token_authentication = '';

	/**
	 * The type of grant to obtain the OAuth 2 access token.
	 *
	 * 	@var string $grant_type
	 *
	 */
	private $grant_type = "authorization_code";

	/**
	 * Option to determine if the access token should be retrieved
	 * using the API key value instead of the client secret.
	 *
	 * @var bool $get_token_with_api_key
	 *
	 */
	private $get_token_with_api_key = false;

	/**
	 * Returns the parameters to add to the OAuth provider
	 * authorization endpoint URL in case of new authentication.
	 *
	 * @return string 
	 */
	public function getReauthenticationParameter() {
		return $this->reauthentication_parameter;
	}

	/**
	 * Returns the parameter to add to the OAuth provider
	 * authorization endpoint URL when offline access is requested.
	 *
	 * @return string 
	 */
	public function getOfflineAccessParameter() {
		return $this->offline_access_parameter;
	}

	/**
	 * Returns The name of the OAuth session state variable,
	 * if different from the standard name,
	 * to work around the implementation bugs of some OAuth providers.
	 *
	 * @return string 
	 */
	public function getAppendStateToRedirectUri() {
		return $this->append_state_to_redirect_uri;
	}

	/**
	 * Checks if the API call parameters should be moved to the
	 * calling URL.
	 *
	 * @return bool 
	 */
	public function isParametersInUrl() {
		return $this->parameters_in_url;
	}

	/**
	 * Checks if the OAuth parameters should be passed via HTTP
	 * Authorization request header.
	 *
	 * @return bool 
	 */
	public function isAuthorizationInHeader() {
		return $this->authorization_in_header;
	}

	/**
	 * Returns the HTTP method that should be used to request
	 * tokens from the server.
	 *
	 * @return string 
	 */
	public function getTokenRequestMethod() {
		return $this->token_request_method;
	}

	/**
	 * Returns the method to generate the signature for API request
	 * parameters values.
	 *
	 * @return string 
	 */
	public function getSignatureMethod() {
		return $this->signature_method;
	}

	/**
	 * Returns the full path of the file
	 * containing a PEM encoded certificate/private key
	 *
	 * @return string 
	 */
	public function getSignatureCertificateFile() {
		return $this->signature_certificate_file;
	}

	/**
	 * Returns the permissions that your application needs to call
	 * the OAuth provider APIs
	 *
	 * @return string 
	 */
	public function getScope() {
		return $this->scope;
	}

	/**
	 * Checks if it will be necessary to call the API when
	 * the user is not present and the server supports renewing expired
	 * access tokens using refresh tokens.
	 *
	 * @return bool 
	 */
	public function isOfflineAccess() {
		return $this->offline_access;
	}

	/**
	 * Checks if it will be necessary to force the user to
	 * authenticate again even after the user has already authorized the
	 * application before.
	 *
	 * @return bool 
	 */
	public function shouldReauthenticate() {
		return $this->reauthenticate;
	}

	/**
	 * Returns the type of access token to be assumed when the OAuth provider
	 * does not specify an access token type.
	 *
	 * @return string 
	 */
	public function getDefaultAccessTokenType() {
		return $this->default_access_token_type;
	}

	/**
	 * Returns the content type to be assumed when retrieving the response to
	 * a request to retrieve the access token.
	 *
	 * @return string 
	 */
	public function getAccessTokenContentType() {
		return $this->access_token_content_type;
	}

	/**
	 * Returns the language to be assumed when retrieving the response to
	 * a request to retrieve the access token.
	 *
	 * @return string 
	 */
	public function getAccessTokenLanguage() {
		return $this->access_token_language;
	}

	/**
	 * Returns the name of the access token parameter to be passed
	 * in API call requests.
	 *
	 * @return string 
	 */
	public function getAccessTokenParameter() {
		return $this->access_token_parameter;
	}

	/**
	 * Checks if the original response for the access
	 * token request should be stored in the
	 * accessTokenResponse variable.
	 *
	 * @return bool 
	 */
	public function shouldStoreAccessTokenResponse() {
		return $this->store_access_token_response;
	}

	/**
	 * Returns the option to determine if the requests to obtain a new access
	 * token should use authentication to pass the application client ID
	 * and secret.
	 *
	 * @return string 
	 */
	public function getAccessTokenAuthentication() {
		return $this->access_token_authentication;
	}

	/**
	 * Returns the option to determine if the requests to refresh an expired
	 * access token should use authentication to pass the application
	 * client ID and secret.
	 *
	 * @return string 
	 */
	public function getRefreshTokenAuthentication() {
		return $this->refresh_token_authentication;
	}

	/**
	 * Returns the type of grant to obtain the OAuth 2 access token.
	 *
	 * @return string 
	 */
	public function getGrantType() {
		return $this->grant_type;
	}

	/**
	 * Checks if the access token should be retrieved
	 * using the API key value instead of the client secret.
	 *
	 * @return bool 
	 */
	public function shouldGetTokenWithApiKey() {
		return $this->get_token_with_api_key;
	}

	/**
	 * Sets the parameters to add to the OAuth provider authorization endpoint URL
	 * in case of new authentication.
	 *
	 * Set this variable when forcing the user to authenticate again
	 * and the format of the of the authorization dialog page URL is
	 * different than the one set to the authorization_endpoint variable.
	 *
	 * @param string $reauthentication_parameter the parameters to add to the OAuth provider authorization endpoint URL
	 *
	 * @return self
	 */
	public function setReauthenticationParameter($reauthentication_parameter) {
		$this->reauthentication_parameter = $reauthentication_parameter;
		return $this;
	}

	/**
	 * Sets the parameter to add to the OAuth provider
	 * authorization endpoint URL when offline access is requested.
	 *
	 * Set this variable to the OAuth request token URL when you are
	 * not accessing one of the built-in OAuth providers and the
	 * OAuth provider supports offline access.
	 * It should have the same format as the authorization_endpoint variable.
	 *
	 * @param string $offline_access_parameter the parameter to add to the OAuth provider authorization endpoint URL
	 *
	 * @return self
	 */
	public function setOfflineAccessParameter($offline_access_parameter) {
		$this->offline_access_parameter = $offline_access_parameter;
		return $this;
	}

	/**
	 * Sets The name of the OAuth session state variable,
	 * if different from the standard name,
	 * to work around the implementation bugs of some OAuth providers.
	 *
	 * Set this variable when you are not accessing one of the
	 * built-in supported OAuth providers if the OAuth provider has a bug
	 * that makes it not pass back the OAuth state identifier in a
	 * request variable named state.
	 *
	 * @param string $append_state_to_redirect_uri The name of the OAuth session state variable
	 *
	 * @return self
	 */
	public function setAppendStateToRedirectUri($append_state_to_redirect_uri) {
		$this->append_state_to_redirect_uri = $append_state_to_redirect_uri;
		return $this;
	}

	/**
	 * Determines if the API call parameters should be moved to the calling URL.
	 *
	 * Set this variable to true if the
	 * API you need to call requires that the call parameters always be
	 * passed via the API URL.
	 *
	 * @param bool $parameters_in_url
	 *
	 * @return self
	 */
	public function setParametersInUrl($parameters_in_url) {
		$this->parameters_in_url = $parameters_in_url;
		return $this;
	}

	/**
	 * Determines if the OAuth parameters should be passed via HTTP
	 * Authorization request header.
	 *
	 * Set this variable to true if the
	 * OAuth provider requires that the OAuth parameters be passed using
	 * the HTTP Authorization instead of the request URI parameters.
	 *
	 * @param bool $authorization_in_header
	 *
	 * @return self
	 */
	public function setAuthorizationHeader($authorization_in_header) {
		$this->authorization_in_header = $authorization_in_header;
		return $this;
	}

	/**
	 * Sets the HTTP method that should be used to request
	 * tokens from the provider.
	 *
	 * Set this variable to 'POST' if the
	 * OAuth provider does not support requesting tokens using the HTTP GET
	 * method.
	 *
	 * @param string $token_request_method the HTTP method
	 *
	 * @return self
	 */
	public function setTokenRequestMethod($token_request_method) {
		$this->token_request_method = $token_request_method;
		return $this;
	}

	/**
	 * Sets the method to generate the signature for API request
	 * parameters values. OAuth 1.0 or 1.0a only.
	 *
	 * Must be one of 'PLAINTEXT', 'HMAC-SHA1' or 'RSA-SHA1'.
	 *
	 * @param string $signature_method the method to generate the signature
	 *
	 * @return self
	 */
	public function setSignatureMethod($signature_method) {
		$this->signature_method = $signature_method;
		return $this;
	}

	/**
	 * Sets the full path of the file containing a PEM encoded certificate/private key
	 *
	 * @param string $signature_certificate_file the full path of the file
	 *
	 * @return self
	 */
	public function setSignatureCertificateFile($signature_certificate_file) {
		$this->signature_certificate_file = $signature_certificate_file;
		return $this;
	}

	/**
	 * Sets the scope, that is to say, the set of permissions
	 * that the application needs to call the OAuth provider APIs
	 *
	 * Check the documentation of the APIs that the application
	 * needs to call to set this variable with the identifiers of the
	 * permissions that the user needs to grant to your application.
	 *
	 * @param string $scope the set of permissions delimited by a space or a comma depending on the provider.
	 *
	 * @return self
	 */
	public function setScope($scope) {
		$this->scope = $scope;
		return $this;
	}

	/**
	 * Determines whether it will be necessary to call the API when
	 * the user is not present and the provider supports renewing expired
	 * access tokens using refresh tokens.
	 *
	 * Set this variable to true if the
	 * provider supports renewing expired tokens automatically when the
	 * user is not present.
	 *
	 * @param bool $offline_access
	 *
	 * @return self
	 */
	public function setOfflineAccess($offline_access) {
		$this->offline_access = $offline_access;
		return $this;
	}

	/**
	 * Determines whether it will be necessary to force the user to
	 * authenticate again even after the user has already authorized the
	 * application before.
	 *
	 * Set this variable to true if you
	 * want to force the user to authenticate again.
	 *
	 * @param bool $reauthenticate
	 *
	 * @return self
	 */
	public function setReauthenticate($reauthenticate) {
		$this->reauthenticate = $reauthenticate;
		return $this;
	}

	/**
	 * Sets the type of access token to be assumed when the OAuth provider
	 * does not specify an access token type.
	 *
	 * Set this variable if the provider requires a certain type of
	 * access token to be used but it does not specify a token type
	 * when the access token is returned.
	 *
	 * @param string $default_access_token_type the type of access token
	 *
	 * @return self
	 */
	public function setDefaultAccessTokenType($default_access_token_type) {
		$this->default_access_token_type = $default_access_token_type;
		return $this;
	}

	/**
	 * Sets the content type to be assumed when retrieving the response to
	 * a request to retrieve the access token.
	 *
	 * Set this variable only if the server does not return the
	 * correct content type for the access token request response.
	 *
	 * @param string $access_token_content_type the content type
	 *
	 * @return self
	 */
	public function setAccessTokenContentType($access_token_content_type) {
		$this->access_token_content_type = $access_token_content_type;
		return $this;
	}

	/**
	 * Sets the language to be assumed when retrieving the response to
	 * a request to retrieve the access token.
	 *
	 * Set this variable only if the provider requires an 'Accept-Language' header
	 * for the access token request response.
	 *
	 * @param string $access_token_language the language
	 *
	 * @return self
	 */
	public function setAccessTokenLanguage($access_token_language) {
		$this->access_token_language = $access_token_language;
		return $this;
	}

	/**
	 * Sets the name of the access token parameter to be passed in API call
	 * requests.
	 *
	 * Set this variable to a non-empty string to override the
	 * default name for the access token parameter which is :
	 *
	 * - 'oauth_token' for OAuth 1.0 and 1.0a
	 * - 'access_token' for OAuth 2.0.
	 *
	 * @param string $access_token_parameter the name of the access token parameter
	 *
	 * @return self
	 */
	public function setAccessTokenParameter($access_token_parameter) {
		$this->access_token_parameter = $access_token_parameter;
		return $this;
	}

	/**
	 * Determines if the original response for the access
	 * token request should be stored in the
	 * accessTokenResponse variable.
	 *
	 * Set this variable to true if the
	 * OAuth provider returns custom parameters in the request to obtain
	 * the access token that may be needed in subsequent API calls.
	 *
	 * @param bool $store_access_token_response
	 *
	 * @return self
	 */
	public function setStoreAccessTokenResponse($store_access_token_response) {
		$this->store_access_token_response = $store_access_token_response;
		return $this;
	}

	/**
	 * Determines if the requests to obtain a new access
	 * token should use authentication to pass the application client ID
	 * and secret.
	 *
	 * Set this variable to 'basic' if the
	 * OAuth provider requires that the the client ID and secret be passed
	 * using HTTP basic authentication headers when retrieving a new
	 * token. Set this variable to 'none' to
	 * avoid that the Authorization header be set in the request to get
	 * the access token.
	 *
	 * @param string $access_token_authentication
	 *
	 * @return self
	 */
	public function setAccessTokenAuthentication($access_token_authentication) {
		$this->access_token_authentication = $access_token_authentication;
		return $this;
	}

	/**
	 * Determines if the requests to refresh an expired
	 * access token should use authentication to pass the application
	 * client ID and secret.
	 *
	 * Leave this value with an empty string to make it use the same
	 * as the access_token_authentication variable.
	 *
	 * Set this variable to 'none' to
	 * avoid that the Authorization header be set in the request to get
	 * the refresh token.
	 *
	 * @param string $refresh_token_authentication
	 *
	 * @return self
	 */
	public function setRefreshTokenAuthentication($refresh_token_authentication) {
		$this->refresh_token_authentication = $refresh_token_authentication;
		return $this;
	}

	/**
	 * Sets the type of grant to obtain the OAuth 2 access token.
	 *
	 * Change this variable to :
	 
	 * - 'client_credentials' to obtain application only access token.
	 * - 'password' to obtain an access token on behalf of an user with a given username and password.
	 * In this case the user does not need to be present,
	 * so the class will not redirect the user to the
	 * authorization dialog page.
	 *
	 * @param string $grant_type the type of grant
	 *
	 * @return self
	 */
	public function setGrantType($grant_type) {
		$this->grant_type = $grant_type;
		return $this;
	}

	/**
	 * Determines if the access token should be retrieved
	 * using the API key value instead of the client secret.
	 *
	 * Set this variable to true if the
	 * OAuth provider requires that the client secret be set to the API key
	 * when retrieving the OAuth token.
	 *
	 * @param bool $get_token_with_api_key
	 *
	 * @return self
	 */
	public function setGetTokenWithApiKey($get_token_with_api_key) {
		$this->get_token_with_api_key = $get_token_with_api_key;
		return $this;
	}

	/**
	 * Binds the configuration options to the properties 
	 * of this instance of the OAuth client strategy.
	 *
	 * @return void
	 *
	 * throws \eureka2\OAuth\Exception\OAuthClientException
	 */
	public function bind($properties) {
		foreach ($properties as $property => $value) {
			if (!isset(self::TYPES[$property])) {
				throw new OAuthClientException('OAuthClientStrategy: ' . $property . ' is not a supported property');
			}
			$type = gettype($value);
			$expected = self::TYPES[$property];
			if ($type !== $expected) {
				throw new OAuthClientException('OAuthClientStrategy: the property "' . $property . '" is not of type "' . $expected . '", it is of type "' . $type);
			}
			$this->{$property} = $value;
		}
	}

	/**
	 * Returns the OAuth strategy as an array
	 *
	 * @return array
	 */
	public function toArray() {
		$config = [
			'reauthentication_parameter' => '',
			'offline_access' => 'boolean',
			'offline_access_parameter' => '',
			'append_state_to_redirect_uri' => '',
			'authorization_in_header' => false,
			'parameters_in_url' => false,
			'token_request_method' => '',
			'signature_method' => '',
			'signature_certificate_file' => '',
			'access_token_authentication' => '',
			'access_token_parameter' => '',
			'default_access_token_type' => '',
			'store_access_token_response' => false,
			'refresh_token_authentication' => '',
			'grant_type' => '',
			'get_token_with_api_key' => false,
			'access_token_content_type' => '',
			'access_token_language' => '',
			'scope' => ''
		];
		$self = $this;
		array_walk($config, function(&$value, $property) use ($self) {
			$value = $self->{$property};
		});
		$config = array_filter($config, function($value) {
			return $value != '';
		});
		return $config;
	}

}

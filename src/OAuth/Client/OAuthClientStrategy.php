<?php declare(strict_types = 1);

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Exception\OAuthClientException;

class OAuthClientStrategy {

	/**
	 * 	URL of the OAuth server to redirect the browser so the user
	 * 	can grant access to your application.
	 *
	 * 	Set this variable when forcing the user to authenticate again
	 * 	and the format of the of the authorization dialog page URL is
	 * 	different than the one set to the authorization_endpoint variable.
	 *
	 * 	@var string $reauthentication_parameter
	 *
	 */
	private $reauthentication_parameter = '';

	/**
	 * 	URL of the OAuth server to redirect the browser so the user
	 * 	can grant access to your application when offline access is
	 * 	requested.
	 *
	 * 	Set this variable to the OAuth request token URL when you are
	 * 	not accessing one of the built-in supported OAuth servers and the
	 * 	OAuth server supports offline access.
	 * 	It should have the same format as the authorization_endpoint variable.
	 *
	 * 	@var string $offline_access_parameter
	 *
	 */
	private $offline_access_parameter = '';

	/**
	 * 	Pass the OAuth session state in a variable with a different
	 * 	name to work around implementation bugs of certain OAuth
	 * 	servers.
	 *
	 * 	Set this variable  when you are not accessing one of the
	 * 	built-in supported OAuth servers if the OAuth server has a bug
	 * 	that makes it not pass back the OAuth state identifier in a
	 * 	request variable named state.
	 *
	 * 	@var string $append_state_to_redirect_uri
	 *
	 */
	private $append_state_to_redirect_uri = '';

	/**
	 * 	Determine if the API call parameters should be moved to the
	 * 	call URL.
	 *
	 * 	Set this variable to true if the
	 * 	API you need to call requires that the call parameters always be
	 * 	passed via the API URL.
	 *
	 * 	@var boolean $url_parameters
	 *
	 */
	private $url_parameters = false;

	/**
	 * 	Determine if the OAuth parameters should be passed via HTTP
	 * 	Authorization request header.
	 *
	 * 	Set this variable to true if the
	 * 	OAuth server requires that the OAuth parameters be passed using
	 * 	the HTTP Authorization instead of the request URI parameters.
	 *
	 * 	@var boolean $authorization_header
	 *
	 */
	private $authorization_header = true;

	/**
	 * 	Define the HTTP method that should be used to request
	 * 	tokens from the server.
	 *
	 * 	Set this variable to 'POST' if the
	 * 	OAuth server does not support requesting tokens using the HTTP GET
	 * 	method.
	 *
	 * 	@var string $token_request_method
	 *
	 */
	private $token_request_method = 'GET';

	/**
	 * 	If Oauth 1.0 or 1.0a, define the method to generate the signature for API request
	 * 	parameters values.
	 *
	 * 	Supports 'PLAINTEXT', 'HMAC-SHA1' and 'RSA-SHA1'.
	 *
	 * 	@var string $signature_method
	 *
	 */
	private $signature_method = 'HMAC-SHA1';

	/**
	 *	If signature_method is 'RSA-SHA1', this variable must contains
	 * 	the full path of the file containing a PEM encoded certificate/private key
	 *
	 * 	@var string $signature_certificate_file
	 *
	 */
	private $signature_certificate_file = '';

	/**
	 * 	Permissions that your application needs to call the OAuth
	 * 	server APIs
	 *
	 * 	Check the documentation of the APIs that your application
	 * 	needs to call to set this variable with the identifiers of the
	 * 	permissions that the user needs to grant to your application.
	 *
	 * 	@var string $scope
	 *
	 */
	private $scope = '';

	/**
	 * 	Specify whether it will be necessary to call the API when
	 * 	the user is not present and the server supports renewing expired
	 * 	access tokens using refresh tokens.
	 *
	 * 	Set this variable to true if the
	 * 	server supports renewing expired tokens automatically when the
	 * 	user is not present.
	 *
	 * 	@var boolean $offline_access
	 *
	 */
	private $offline_access = false;

	/**
	 * 	Specify whether it will be necessary to force the user to
	 * 	authenticate again even after the user has already authorized the
	 * 	application before.
	 *
	 * 	Set this variable to true if you
	 * 	want to force the user to authenticate again.
	 *
	 * 	@var boolean $reauthenticate
	 *
	 */
	private $reauthenticate = false;

	/**
	 * 	Type of access token to be assumed when the OAuth server
	 * 	does not specify an access token type.
	 *
	 * 	Set this variable if the server requires a certain type of
	 * 	access token to be used but it does not specify a token type
	 * 	when the access token is returned.
	 *
	 * 	@var string $default_access_token_type
	 *
	 */
	private $default_access_token_type = '';

	/**
	 * 	Content type to be assumed when retrieving the response to
	 * 	a request to retrieve the access token.
	 *
	 * 	Set this variable only if the server does not return the
	 * 	correct content type for the access token request response.
	 *
	 * 	@var string $access_token_content_type
	 *
	 */
	private $access_token_content_type = '';

	/**
	 * 	Language to be assumed when retrieving the response to
	 * 	a request to retrieve the access token.
	 *
	 * 	Set this variable only if the server requires an 'Accept-Language' header
	 *  for the access token request response.
	 *
	 * 	@var string $access_token_language
	 *
	 */
	private $access_token_language = '';

	/**
	 * 	Name of the access token parameter to be passed in API call
	 * 	requests.
	 *
	 * 	Set this variable to a non-empty string to override the
	 * 	default name for the access token parameter which is
	 * 	'oauth_token' of OAuth 1 and
	 * 	'access_token' for OAuth 2.
	 *
	 * 	@var string $access_token_parameter
	 *
	 */
	private $access_token_parameter = '';

	/**
	 * 	Option to determine if the original response for the access
	 * 	token request should be stored in the
	 * 	accessTokenResponse variable.
	 *
	 * 	Set this variable to true if the
	 * 	OAuth server returns custom parameters in the request to obtain
	 * 	the access token that may be needed in subsequent API calls.
	 *
	 * 	@var boolean $store_access_token_response
	 *
	 */
	private $store_access_token_response = false;

	/**
	 * 	Option to determine if the requests to obtain a new access
	 * 	token should use authentication to pass the application client ID
	 * 	and secret.
	 *
	 * 	Set this variable to 'basic' if the
	 * 	OAuth server requires that the the client ID and secret be passed
	 * 	using HTTP basic authentication headers when retrieving a new
	 * 	token. Set this variable to 'none' to
	 * 	avoid that the Authorization header be set in the request to get
	 * 	the access token.
	 *
	 * 	@var string $access_token_authentication
	 *
	 */
	private $access_token_authentication = '';

	/**
	 * 	Option to determine if the requests to refresh an expired
	 * 	access token should use authentication to pass the application
	 * 	client ID and secret.
	 *
	 * 	Leave this value with an empty string to make it use the same
	 * 	as the @link access_token_authentication variable.
	 *
	 * 	Set this variable to 'none' to
	 * 	avoid that the Authorization header be set in the request to get
	 * 	the refresh token.
	 *
	 * 	@var string $refresh_token_authentication
	 *
	 */
	private $refresh_token_authentication = '';

	/**
	 * 	Define the type of grant to obtain the OAuth 2 access token.
	 * 	Change this variable to :
	 * 		'client_credentials' to obtain application only access token.
	 * 		'password' to obtain an access token on behalf of an user with a given username and password.
	 * 			In this case the user does not need to be present,
	 * 			so the class will not redirect the user to the
	 * 			authorization dialog page.
	 *
	 * 	@var string $grant_type
	 *
	 */
	private $grant_type = "authorization_code";

	/**
	 * 	Option to determine if the access token should be retrieved
	 * 	using the API key value instead of the client secret.
	 *
	 * 	Set this variable to true if the
	 * 	OAuth server requires that the client secret be set to the API key
	 * 	when retrieving the OAuth token.
	 *
	 * 	@var boolean $get_token_with_api_key
	 *
	 */
	private $get_token_with_api_key = false;

	public function getReauthenticationParameter() {
		return $this->reauthentication_parameter;
	}

	public function getOfflineAccessParameter() {
		return $this->offline_access_parameter;
	}

	public function getAppendStateToRedirectUri() {
		return $this->append_state_to_redirect_uri;
	}

	public function isUrlParameters() {
		return $this->url_parameters;
	}

	public function isAuthorizationInHeader() {
		return $this->authorization_header;
	}

	public function getTokenRequestMethod() {
		return $this->token_request_method;
	}

	public function getSignatureMethod() {
		return $this->signature_method;
	}

	public function getSignatureCertificateFile() {
		return $this->signature_certificate_file;
	}

	public function getScope() {
		return $this->scope;
	}

	public function isOfflineAccess() {
		return $this->offline_access;
	}

	public function shouldReauthenticate() {
		return $this->reauthenticate;
	}

	public function getDefaultAccessTokenType() {
		return $this->default_access_token_type;
	}

	public function getAccessTokenContentType() {
		return $this->access_token_content_type;
	}

	public function getAccessTokenLanguage() {
		return $this->access_token_language;
	}

	public function getAccessTokenParameter() {
		return $this->access_token_parameter;
	}

	public function shouldStoreAccessTokenResponse() {
		return $this->store_access_token_response;
	}

	public function getAccessTokenAuthentication() {
		return $this->access_token_authentication;
	}

	public function getRefreshTokenAuthentication() {
		return $this->refresh_token_authentication;
	}

	public function getGrantType() {
		return $this->grant_type;
	}

	public function getTokenWithApiKey() {
		return $this->get_token_with_api_key;
	}

	public function setReauthenticationParameter($reauthentication_parameter) {
		$this->reauthentication_parameter = $reauthentication_parameter;
		return $this;
	}

	public function setOfflineAccessParameter($offline_access_parameter) {
		$this->offline_access_parameter = $offline_access_parameter;
		return $this;
	}

	public function setAppendStateToRedirectUri($append_state_to_redirect_uri) {
		$this->append_state_to_redirect_uri = $append_state_to_redirect_uri;
		return $this;
	}

	public function setUrlParameters($url_parameters) {
		$this->url_parameters = $url_parameters;
		return $this;
	}

	public function setAuthorizationHeader($authorization_header) {
		$this->authorization_header = $authorization_header;
		return $this;
	}

	public function setTokenRequestMethod($token_request_method) {
		$this->token_request_method = $token_request_method;
		return $this;
	}

	public function setSignatureMethod($signature_method) {
		$this->signature_method = $signature_method;
		return $this;
	}

	public function setSignatureCertificateFile($signature_certificate_file) {
		$this->signature_certificate_file = $signature_certificate_file;
		return $this;
	}

	public function setScope($scope) {
		$this->scope = $scope;
		return $this;
	}

	public function setOfflineAccess($offline_access) {
		$this->offline_access = $offline_access;
		return $this;
	}

	public function setReauthenticate($reauthenticate) {
		$this->reauthenticate = $reauthenticate;
		return $this;
	}

	public function setDefaultAccessTokenType($default_access_token_type) {
		$this->default_access_token_type = $default_access_token_type;
		return $this;
	}

	public function setAccessTokenContentType($access_token_content_type) {
		$this->access_token_content_type = $access_token_content_type;
		return $this;
	}

	public function setAccessTokenLanguage($access_token_language) {
		$this->access_token_language = $access_token_language;
		return $this;
	}

	public function setAccessTokenParameter($access_token_parameter) {
		$this->access_token_parameter = $access_token_parameter;
		return $this;
	}

	public function setStoreAccessTokenResponse($store_access_token_response) {
		$this->store_access_token_response = $store_access_token_response;
		return $this;
	}

	public function setAccessTokenAuthentication($access_token_authentication) {
		$this->access_token_authentication = $access_token_authentication;
		return $this;
	}

	public function setRefreshTokenAuthentication($refresh_token_authentication) {
		$this->refresh_token_authentication = $refresh_token_authentication;
		return $this;
	}

	public function setGrantType($grant_type) {
		$this->grant_type = $grant_type;
		return $this;
	}

	public function setGetTokenWithApiKey($get_token_with_api_key) {
		$this->get_token_with_api_key = $get_token_with_api_key;
		return $this;
	}

	public function bind($properties) {
		$types = [
			'reauthentication_parameter' => 'string',
			'offline_access' => 'boolean',
			'offline_access_parameter' => 'string',
			'append_state_to_redirect_uri' => 'string',
			'authorization_header' => 'boolean',
			'url_parameters' => 'boolean',
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
		foreach ($properties as $property => $value) {
			if (!isset($types[$property])) {
				throw new OAuthClientException('OAuthClientStrategy: ' . $property . ' is not a supported property');
			}
			$type = gettype($value);
			$expected = $types[$property];
			if ($type !== $expected) {
				throw new OAuthClientException('OAuthClientStrategy: the property "' . $property . '" is not of type "' . $expected . '", it is of type "' . $type);
			}
			$this->{$property} = $value;
		}
	}

}

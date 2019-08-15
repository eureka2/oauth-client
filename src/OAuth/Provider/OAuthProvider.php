<?php

namespace eureka2\OAuth\Provider;

use eureka2\OAuth\Exception\OAuthClientException;

class OAuthProvider {

	/** @var string */
	private $name = '';

	/** @var string */
	private $protocol = 'oauth';

	/** @var string */
	private $version = '2.0';

	/** @var string */
	private $client_id = '';

	/** @var string */
	private $client_secret = '';

	/** @var string */
	private $redirect_uri = '';

	/** @var string */
	private $discovery_endpoint = '';

	/**
	 *
	 * 	@var string $authorization_endpoint
	 * 	URL of the OAuth server to redirect the browser so the user
	 * 	can grant access to your application.
	 * 	Set this variable to the OAuth request token URL when you are
	 * 	not accessing one of the built-in supported OAuth servers.
	 * 	For OAuth 1.0a servers that return the login dialog URL
	 * 	automatically, set this variable to 'automatic'
	 * 	For OAuth 1.0a servers that support 2 legged authentication set
	 * 	this variable to '2legged'
	 * 	For certain servers, the dialog URL can have certain marks that
	 * 	will act as template placeholders which will be replaced with
	 * 	values defined before redirecting the users browser. Currently it
	 * 	supports the following placeholder marks:
	 * 	{REDIRECT_URI} - URL to redirect when returning from the OAuth
	 * 	server authorization page
	 * 	{CLIENT_ID} - client application identifier registered at the
	 * 	server
	 * 	{SCOPE} - scope of the requested permissions to the granted by the
	 * 	OAuth server with the user permissions
	 * 	{STATE} - identifier of the OAuth session state
	 * 	{API_KEY} - API key to access the server
	 * 	{REALM} - realm name for OpenID Connect
	 * 	{NONCE} - unique identifier to made all redirects be unique for
	 * 	OpenID Connect
	 *
	 */
	private $authorization_endpoint = '';

	/** @var string */
	private $token_endpoint = '';

	/** @var string */
	private $registration_endpoint = '';

	/** @var string */
	private $introspection_endpoint = '';

	/** @var string */
	private $revocation_endpoint = '';

	/**
	 *
	 * 	@var string $request_token_endpoint
	 * 	URL of the OAuth server to request the initial token for OAuth 1.0 and 1.0a servers.
	 *
	 * 	Set this variable to the OAuth request token URL when you are
	 * 	not accessing one of the built-in supported OAuth servers.
	 *
	 * 	For OAuth 1.0 and 1.0a servers, the request token URL can have
	 * 	certain marks that will act as template placeholders which will be
	 * 	replaced with given values before requesting the authorization
	 * 	token. Currently it supports the following placeholder marks:
	 * 	{SCOPE} - scope of the requested permissions to the granted by the OAuth server with the user permissions
	 *
	 */
	private $request_token_endpoint = '';

	/** @var string */
	private $userinfo_endpoint = '';

	/** @var string */
	private $end_session_endpoint = '';

	/** @var string */
	private $jwks_uri = '';

	/** @var array */
	private $scopes_supported = [];

	/** @var array */
	private $response_types_supported = [];

	/** @var array */
	private $response_modes_supported = [];

	/** @var array */
	private $token_endpoint_auth_methods_supported = [];

	/** @var array */
	private $subject_types_supported = [];

	/** @var array */
	private $id_token_signing_alg_values_supported = [];

	/** @var array */
	private $claims_supported = [];

	/** @var string */
	private $user_id_field = 'sub';

	/** @var string */
	private $api_key = '';

	/**
	 * @param string $name
	 */
	public function __construct($name, $client_id = '', $client_secret = '', $redirect_uri = '') {
		$this->name = $name;
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->redirect_uri = $redirect_uri;
	}

	public function getName() {
		return $this->name;
	}

	public function getProtocol() {
		return $this->protocol;
	}

	public function getVersion() {
		return $this->version;
	}

	public function getClientId() {
		return $this->client_id;
	}

	public function getClientSecret() {
		return $this->client_secret;
	}

	public function getRedirectUri() {
		return $this->redirect_uri;
	}

	public function getDiscoveryEndpoint() {
		return $this->discovery_endpoint;
	}

	public function getAuthorizationEndpoint() {
		return $this->authorization_endpoint;
	}

	public function getTokenEndpoint() {
		return $this->token_endpoint;
	}

	public function getRegistrationEndpoint() {
		return $this->registration_endpoint;
	}

	public function getIntrospectionEndpoint() {
		return $this->introspection_endpoint;
	}

	public function getRevocationEndpoint() {
		return $this->revocation_endpoint;
	}

	public function getRequestTokenEndpoint() {
		return $this->request_token_endpoint;
	}

	public function getUserinfoEndpoint() {
		return $this->userinfo_endpoint;
	}

	public function getEndSessionEndpoint() {
		return $this->end_session_endpoint;
	}

	public function getJwksUri() {
		return $this->jwks_uri;
	}

	public function getScopesSupported() {
		return $this->scopes_supported;
	}

	public function getResponseTypesSupported() {
		return $this->response_types_supported;
	}

	public function getResponseModesSupported() {
		return $this->response_modes_supported;
	}

	public function getTokenEndpointAuthMethodsSupported() {
		return $this->token_endpoint_auth_methods_supported;
	}

	public function getSubjectTypesSupported() {
		return $this->subject_types_supported;
	}

	public function getIdTokenSigningAlgValuesSupported() {
		return $this->id_token_signing_alg_values_supported;
	}

	public function getClaimsSupported() {
		return $this->claims_supported;
	}

	public function getUserIdField() {
		return $this->user_id_field;
	}

	public function getApiKey() {
		return $this->api_key;
	}

	public function setVersion($version) {
		$this->version = $version;
		return $this;
	}

	public function setProtocol($protocol) {
		$this->protocol = $protocol;
		return $this;
	}

	public function setClientId($client_id) {
		$this->client_id = $client_id;
		return $this;
	}

	public function setClientSecret($client_secret) {
		$this->client_secret = $client_secret;
		return $this;
	}

	public function setRedirectUri($redirect_uri) {
		$this->redirect_uri = $redirect_uri;
		return $this;
	}

	public function setDiscoveryEndpoint($discovery_endpoint) {
		$this->discovery_endpoint = $discovery_endpoint;
		return $this;
	}

	public function setAuthorizationEndpoint($authorization_endpoint) {
		$this->authorization_endpoint = $authorization_endpoint;
		return $this;
	}

	public function setTokenEndpoint($token_endpoint) {
		$this->token_endpoint = $token_endpoint;
		return $this;
	}

	public function setRegistrationEndpoint($registration_endpoint) {
		$this->registration_endpoint = $registration_endpoint;
		return $this;
	}

	public function setIntrospectionEndpoint($introspection_endpoint) {
		$this->introspection_endpoint = $introspection_endpoint;
		return $this;
	}

	public function setRevocationEndpoint($revocation_endpoint) {
		$this->revocation_endpoint = $revocation_endpoint;
		return $this;
	}

	public function setRequestTokenEndpoint($request_token_endpoint) {
		$this->request_token_endpoint = $request_token_endpoint;
		return $this;
	}

	public function setUserinfoEndpoint($userinfo_endpoint) {
		$this->userinfo_endpoint = $userinfo_endpoint;
		return $this;
	}

	public function setEndSessionEndpoint($end_session_endpoint) {
		$this->end_session_endpoint = $end_session_endpoint;
		return $this;
	}

	public function setJwksUri($jwks_uri) {
		$this->jwks_uri = $jwks_uri;
		return $this;
	}

	public function setScopesSupported($scopes_supported) {
		$this->scopes_supported = $scopes_supported;
		return $this;
	}

	public function setResponseTypesSupported($response_types_supported) {
		$this->response_types_supported = $response_types_supported;
		return $this;
	}

	public function setResponseModesSupported($response_modes_supported) {
		$this->response_modes_supported = $response_modes_supported;
		return $this;
	}

	public function setTokenEndpointAuthMethodsSupported($token_endpoint_auth_methods_supported) {
		$this->token_endpoint_auth_methods_supported = $token_endpoint_auth_methods_supported;
		return $this;
	}

	public function setSubjectTypesSupported($subject_types_supported) {
		$this->subject_types_supported = $subject_types_supported;
		return $this;
	}

	public function setIdTokenSigningAlgValuesSupported($id_token_signing_alg_values_supported) {
		$this->id_token_signing_alg_values_supported = $id_token_signing_alg_values_supported;
		return $this;
	}

	public function setClaimsSupported($claims_supported) {
		$this->claims_supported = $claims_supported;
		return $this;
	}

	public function setUserIdField($user_id_field) {
		$this->user_id_field = $user_id_field;
		return $this;
	}

	public function setApiKey($api_key) {
		$this->api_key = $api_key;
		return $this;
	}

	public function bind($configuration) {
		$types = [
			'protocol' => 'string',
			'version' => 'string',
			'discovery_endpoint' => 'string',
			'authorization_endpoint' => 'string',
			'token_endpoint' => 'string',
			'registration_endpoint' => 'string',
			'introspection_endpoint' => 'string',
			'revocation_endpoint' => 'string',
			'request_token_endpoint' => 'string',
			'userinfo_endpoint' => 'string',
			'end_session_endpoint' => 'string',
			'jwks_uri' => 'string',
			'scopes_supported' => 'array',
			'response_types_supported' => 'array',
			'response_modes_supported' => 'array',
			'token_endpoint_auth_methods_supported' => 'array',
			'subject_types_supported' => 'array',
			'id_token_signing_alg_values_supported' => 'array',
			'claims_supported' => 'array',
			'user_id_field' => 'string',
			'api_key' => 'string'
		];
		$required = [
			'protocol' => '',
			'version' => '',
			'authorization_endpoint' => [],
			'token_endpoint' => []
		];
		foreach ($configuration as $property => $value) {
			if (!isset($types[$property])) {
				throw new OAuthClientException('OAuthProvider: ' . $property . ' is not a supported property');
			}
			$type = gettype($value);
			$expected = $types[$property];
			if ($type !== $expected) {
				throw new OAuthClientException('OAuthProvider: the property "' . $property . '" is not of type "' . $expected . '", it is of type "' . $type);
			}
			$this->{$property} = $value;
			unset($required[$property]);
		}
		foreach ($required as $property => $value) {
			if (count($value) && in_array($this->getVersion(), $value)) {
				throw new OAuthClientException('OAuthProvider: the property "' . $property . '" must be defined');
			}
		}
	}

}

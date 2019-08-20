<?php declare(strict_types = 1);

namespace eureka2\OAuth\Provider;

use eureka2\OAuth\Exception\OAuthClientException;

class OAuthProvider {

	/**
	 * @var string $name the name of the provider
	 *
	 */
	private $name = '';

	/**
	 * @var string $protocol
	 *
	 */
	private $protocol = 'oauth';

	/**
	 * @var string $version
	 * Version of the protocol version supported by the OAuth provider.
	 * Supported versions are '1.0', '1.0a', '2.0' for the 'oauth' protocol
	 * and '1.0' for the openid protocol.
	 *
	 */
	private $version = '2.0';

	/**
	 * @var string $client_id
	 * Identifier of your application registered with the OAuth provider.
	 * Set this variable to the application identifier that is
	 * provided by the OAuth provider when you register the application.
	 *
	 */
	private $client_id = '';

	/**
	 * @var string $client_secret
	 * Secret value assigned to your application when it is registered with the OAuth provider.
	 * Set this variable to the application secret that is provided
	 * by the OAuth server when you register the application.
	 *
	 */
	private $client_secret = '';

	/**
	 * @var string $redirect_uri
	 * URL of the current script page that is calling this class.
	 * Set this variable to the current script page URL
	 * before proceeding the the OAuth authorization process.
	 * This url must be registered with the identity provider.
	 * For pin based authorization, set this variable to 'oob'.
	 */
	private $redirect_uri = '';

	/**
	 * @var string $discovery_endpoint
	 *
	 */
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

	/**
	 * @var string $token_endpoint
	 * The token endpoint is the URL of the OAuth provider
	 * used by a client to obtain an ID token, access token, and refresh token
	 *
	 */
	private $token_endpoint = '';

	/**
	 * @var string $registration_endpoint
	 * The client registration endpoint is an administrator managed service
	 * that is used to dynamically register, update, delete, and retrieve information
	 * about an OpenID Connect Relying Party that intends to use the OpenID Connect Provider
	 * In turn, the registration process can provide information for the Relying Party to use it,
	 * including the OAuth 2.0 Client ID and Client Secret, if not specified.
	 *
	 */
	private $registration_endpoint = '';

	/**
	 * @var string $introspection_endpoint
	 * The introspection endpoint enables holders of access tokens to request a set of metadata
	 * about an access token from the OpenID Connect Provider that issued the access token.
	 * The access token must be one that was obtained through OpenID Connect or OAuth authentication.
	 *
	 */
	private $introspection_endpoint = '';

	/**
	 * @var string $revocation_endpoint
	 * The revocation endpoint enables clients to notify the OpenID Connect Provider
	 * that an issued token is no longer needed and must be revoked.
	 * The revocation endpoint can revoke a token that was obtained through OAuth authentication.
	 *
	 */
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

	/**
	 * @var string $userinfo_endpoint
	 * The UserInfo endpoint returns claims about a user
	 * that is authenticated with OAuth authentication.
	 *
	 */
	private $userinfo_endpoint = '';

	/**
	 * @var string $end_session_endpoint
	 * The end session endpoint allow a client to clear the provider-side session
	 * and cookies for a web browser.
	 *
	 */
	private $end_session_endpoint = '';

	/**
	 * 	@var string $pin_dialog_url
	 * 	URL of the OAuth server to redirect the browser so the user
	 * 	can grant access to your application.
	 *
	 * 	Set this variable when using the pin based authorization and
	 * 	the format of the of the authorization dialog page URL is
	 * 	different than the one set to the authorization_endpoint variable.
	 *
	 */
	private $pin_dialog_url = '';

	/**
	 *
	 * 	@var string $pin
	 * 	Value of the pin code for pin based authorization.
	 * 	Set this value to the pin informed by the user when
	 * 	implementing the pin based authorization.
	 * 	Make sure the  redirect_uri variable
	 * 	is set to 'oob'.
	 *
	 */
	private $pin = '';

	/**
	 * @var string $jwks_uri
	 * jwks_uri is a metadata entry expressed as a URI for the OAuth Provider's JWK Set
	 * or OAuth Client (Relying Party which contains a JSONArray of the JSON Web Keys (JWK)
	 * used for JSON Web Signature and/or JSON Web Encryption keys (JWK).
	 *
	 * jwks_uri is used within the OAuth Provider and the OAuth Client.
	 *
	 */
	private $jwks_uri = '';

	/**
	 * @var array $scopes_supported
	 * Array containing a list of the OAuth 2.0 scope values that this provider supports.
	 * An OpenID provider must support the openid scope value.
	 *
	 */
	private $scopes_supported = [];

	/**
	 * @var array $response_types_supported
	 * Array containing a list of the OAuth 2.0 response_type values that this provider supports.
	 * Dynamic OpenID Providers MUST support the code, id_token, and the token id_token Response Type values.
	 *
	 */
	private $response_types_supported = [];

	/**
	 * @var array $response_modes_supported
	 * Array containing a list of the OAuth 2.0 response_mode values that this provider supports,
	 * as specified in OAuth 2.0 Multiple Response Type Encoding Practices [OAuth.Responses].
	 * If omitted, the default for dynamic OpenID providers is ["query", "fragment"].
	 *
	 */
	private $response_modes_supported = [];

	/**
	 * @var array $token_endpoint_auth_methods_supported
	 * Array containing a list of client authentication methods supported by this token endpoint.
	 * The options are "client_secret_post", "client_secret_basic", "client_secret_jwt", and "private_key_jwt",
	 * as described in Section 9 of OpenID Connect Core 1.0 [OpenID.Core].
	 * Other authentication methods may be defined by extensions. 
	 * If omitted, the default is client_secret_basic.
	 *
	 */
	private $token_endpoint_auth_methods_supported = [];

	/**
	 * @var array $subject_types_supported
	 * Array containing a list of the Subject Identifier types that this provider supports.
	 * Valid types include "pairwise" and "public".
	 *
	 */
	private $subject_types_supported = [];

	/**
	 * @var array $id_token_signing_alg_values_supported
	 * Array containing a list of the JWS signing algorithms (alg values) supported by the provider
	 * for the ID Token to encode the Claims in a JWT [JWT].
	 * The algorithm RS256 must be included.
	 * The value none may be supported, but must not be used
	 * unless the Response Type used returns no ID Token from the Authorization Endpoint
	 * (such as when using the Authorization Code Flow).
	 *
	 */
	private $id_token_signing_alg_values_supported = [];

	/**
	 * @var array $claims_supported
	 * Array containing a list of the Claim Names of the Claims that the OpenID Provider
	 * may be able to supply values for.
	 * Note that for privacy or other reasons, this might not be an exhaustive list.
	 *
	 */
	private $claims_supported = [];

	/**
	 * @var string $user_id_field
	 * The name of the field in the ID token returned by the provider 
	 * that represents the user's invariant identifier.
	 * This field can be used for the account linking.
	 *
	 */
	private $user_id_field = 'sub';

	/**
	 * @var string $api_key
	 * Identifier of your API key provided by the OAuth server.
	 * Set this variable to the API key if the OAuth server requires one.
	 *
	 */
	private $api_key = '';

	/**
	 * 	@var string $oauth_username
	 * 	Define the user name to obtain authorization using a password.
	 *
	 * 	Set this variable to the user name of the account to
	 * 	authorize instead of going through the interactive user
	 * 	authorization process.
	 *
	 */
	private $oauth_username = '';

	/**
	 * 	@var string $oauth_password
	 * 	Define the user name to obtain authorization using a password.
	 *
	 * 	Set this variable to the user password of the account to
	 * 	authorize instead of going through the interactive user
	 * 	authorization process.
	 *
	 */
	private $oauth_password = '';

	/**
	 * 	@var string $realm
	 * 	Realm of authorization for OpenID Connect
	 *
	 * 	Set this variable to the realm value when using OpenID Connect.
	 *
	 */
	private $realm = '';

	/**
	 * Constructs a OAuthProvider instance with the registered data of the client
	 * with the OAuth provider.
	 *
	 * @param string $name The name of the OAuth provider
	 * @param string $client_id The identifier of your application registered with the OAuth provider
	 * @param string $client_secret The secret value assigned to your application
	 * @param string $redirect_uri The URL of the current script page that is calling this class
	 *
	 */
	public function __construct(string $name, string $client_id = '', string $client_secret = '', string $redirect_uri = '') {
		$this->name = $name;
		$this->client_id = $client_id;
		$this->client_secret = $client_secret;
		$this->redirect_uri = $redirect_uri;
	}

	public function getName() : string {
		return $this->name;
	}

	public function getProtocol() : string {
		return $this->protocol;
	}

	public function getVersion() : string {
		return $this->version;
	}

	public function getClientId() : string {
		return $this->client_id;
	}

	public function getClientSecret() : string {
		return $this->client_secret;
	}

	public function getRedirectUri() : string {
		return $this->redirect_uri;
	}

	public function getDiscoveryEndpoint() : string {
		return $this->discovery_endpoint;
	}

	public function getAuthorizationEndpoint() : string {
		return $this->authorization_endpoint;
	}

	public function getTokenEndpoint() : string {
		return $this->token_endpoint;
	}

	public function getRegistrationEndpoint() : string {
		return $this->registration_endpoint;
	}

	public function getIntrospectionEndpoint() : string {
		return $this->introspection_endpoint;
	}

	public function getRevocationEndpoint() : string {
		return $this->revocation_endpoint;
	}

	public function getRequestTokenEndpoint() : string {
		return $this->request_token_endpoint;
	}

	public function getUserinfoEndpoint() : string {
		return $this->userinfo_endpoint;
	}

	public function getEndSessionEndpoint() : string {
		return $this->end_session_endpoint;
	}

	public function getPinDialogUrl() : string {
		return $this->pin_dialog_url;
	}

	public function getPin() : string {
		return $this->pin;
	}

	public function getJwksUri() : string {
		return $this->jwks_uri;
	}

	public function getScopesSupported() : array {
		return $this->scopes_supported;
	}

	public function getResponseTypesSupported() : array {
		return $this->response_types_supported;
	}

	public function getResponseModesSupported() : array {
		return $this->response_modes_supported;
	}

	public function getTokenEndpointAuthMethodsSupported() : array {
		return $this->token_endpoint_auth_methods_supported;
	}

	public function getSubjectTypesSupported() : array {
		return $this->subject_types_supported;
	}

	public function getIdTokenSigningAlgValuesSupported() : array {
		return $this->id_token_signing_alg_values_supported;
	}

	public function getClaimsSupported() : array {
		return $this->claims_supported;
	}

	public function getUserIdField() : string {
		return $this->user_id_field;
	}

	public function getApiKey() : string {
		return $this->api_key;
	}

	public function getOauthUsername() : string {
		return $this->oauth_username;
	}

	public function getOauthPassword() : string {
		return $this->oauth_password;
	}

	public function getRealm() : string {
		return $this->realm;
	}

	public function setVersion(string $version) {
		$this->version = $version;
		return $this;
	}

	public function setProtocol(string $protocol) {
		$this->protocol = $protocol;
		return $this;
	}

	public function setClientId(string $client_id) {
		$this->client_id = $client_id;
		return $this;
	}

	public function setClientSecret(string $client_secret) {
		$this->client_secret = $client_secret;
		return $this;
	}

	public function setRedirectUri(string $redirect_uri) {
		$this->redirect_uri = $redirect_uri;
		return $this;
	}

	public function setDiscoveryEndpoint(string $discovery_endpoint) {
		$this->discovery_endpoint = $discovery_endpoint;
		return $this;
	}

	public function setAuthorizationEndpoint(string $authorization_endpoint) {
		$this->authorization_endpoint = $authorization_endpoint;
		return $this;
	}

	public function setTokenEndpoint(string $token_endpoint) {
		$this->token_endpoint = $token_endpoint;
		return $this;
	}

	public function setRegistrationEndpoint(string $registration_endpoint) {
		$this->registration_endpoint = $registration_endpoint;
		return $this;
	}

	public function setIntrospectionEndpoint(string $introspection_endpoint) {
		$this->introspection_endpoint = $introspection_endpoint;
		return $this;
	}

	public function setRevocationEndpoint(string $revocation_endpoint) {
		$this->revocation_endpoint = $revocation_endpoint;
		return $this;
	}

	public function setRequestTokenEndpoint(string $request_token_endpoint) {
		$this->request_token_endpoint = $request_token_endpoint;
		return $this;
	}

	public function setUserinfoEndpoint(string $userinfo_endpoint) {
		$this->userinfo_endpoint = $userinfo_endpoint;
		return $this;
	}

	public function setEndSessionEndpoint(string $end_session_endpoint) {
		$this->end_session_endpoint = $end_session_endpoint;
		return $this;
	}

	public function setPinDialogUrl(string $pin_dialog_url) {
		$this->pin_dialog_url = $pin_dialog_url;
		return $this;
	}

	public function setPin(string $pin) {
		$this->pin = $pin;
		return $this;
	}

	public function setJwksUri(string $jwks_uri) {
		$this->jwks_uri = $jwks_uri;
		return $this;
	}

	public function setScopesSupported(array $scopes_supported) {
		$this->scopes_supported = $scopes_supported;
		return $this;
	}

	public function setResponseTypesSupported(array $response_types_supported) {
		$this->response_types_supported = $response_types_supported;
		return $this;
	}

	public function setResponseModesSupported(array $response_modes_supported) {
		$this->response_modes_supported = $response_modes_supported;
		return $this;
	}

	public function setTokenEndpointAuthMethodsSupported(array $token_endpoint_auth_methods_supported) {
		$this->token_endpoint_auth_methods_supported = $token_endpoint_auth_methods_supported;
		return $this;
	}

	public function setSubjectTypesSupported(array $subject_types_supported) {
		$this->subject_types_supported = $subject_types_supported;
		return $this;
	}

	public function setIdTokenSigningAlgValuesSupported(array $id_token_signing_alg_values_supported) {
		$this->id_token_signing_alg_values_supported = $id_token_signing_alg_values_supported;
		return $this;
	}

	public function setClaimsSupported(array $claims_supported) {
		$this->claims_supported = $claims_supported;
		return $this;
	}

	public function setUserIdField(string $user_id_field) {
		$this->user_id_field = $user_id_field;
		return $this;
	}

	public function setApiKey(string $api_key) {
		$this->api_key = $api_key;
		return $this;
	}

	public function setOauthUsername(string $oauth_username) {
		$this->oauth_username = $oauth_username;
		return $this;
	}

	public function setOauthPassword(string $oauth_password) {
		$this->oauth_password = $oauth_password;
		return $this;
	}

	public function setRealm(string $realm) {
		$this->realm = $realm;
		return $this;
	}

	public function bind(array $configuration) {
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
			'pin_dialog_url' => 'string',
			'jwks_uri' => 'string',
			'scopes_supported' => 'array',
			'response_types_supported' => 'array',
			'response_modes_supported' => 'array',
			'token_endpoint_auth_methods_supported' => 'array',
			'subject_types_supported' => 'array',
			'id_token_signing_alg_values_supported' => 'array',
			'claims_supported' => 'array',
			'user_id_field' => 'string'
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

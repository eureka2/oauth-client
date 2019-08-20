<?php declare(strict_types = 1);

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Exception\OAuthClientException;

interface OAuthClientInterface {

	/**
	 * 	Initialize the class variables and internal state. It must
	 * 	be called before calling other class functions.
	 *
	 * 	Set the provider variable before
	 * 	calling this function to let it initialize the class variables to
	 * 	work with the specified provider. Alternatively, you can set
	 * 	other class variables manually to make it work with providers that
	 * 	are not yet built-in supported.
	 *
	 * 	@options array $options class variables to work with the specified provider.
	 *
	 * 	@return bool This function returns true if it was able to successfully initialize the class for the specified server type.
	 *
	 */
	public function initialize($options = []);

	/**
	 * 	Process the OAuth protocol interaction with the OAuth provider.
	 *
	 * 	Call this function when you need to retrieve the OAuth access token.
	 * 	Check the access_token to determine if the access token was obtained successfully.
	 *
	 * 	@return bool This function returns true if the OAuth protocol was processed without errors.
	 *
	 */
	public function authenticate();

	/**
	 * 	Send a HTTP request to the Web services API using a
	 * 	previously obtained access token via OAuth.
	 *
	 * 	This function can be used to call an API after having
	 * 	previously obtained an access token through the OAuth protocol
	 * 	using the authenticate function, or by directly setting the variables
	 * 	access_token, as well as access_token_secret in case of using OAuth 1.0 or 1.0a services.
	 * 	The response_status variable returns the HTTP response status of the request.
	 * 	The responseHeaders variable returns the HTTP response headers.
	* 	The responseBody variable returns the HTTP response body.
	 *
	 * 	@param string $url URL of the API where the HTTP request will be sent.
	 *
	 * 	@param string $method HTTP method that will be used to send the request. It can be 'GET', 'POST', 'DELETE', 'PUT', etc..
	 *
	 * 	@param array $parameters Associative array with the names and values of the API call request parameters.
	 *
	 * 	@param array $options Associative array with additional options to configure the request.
	 * 	    Currently it supports the following options:
	 * 	        '2legged'                : boolean option that determines if the API request should be 2 legged. The default value is false.
	 * 	        'accept'                 : content type value of the Accept HTTP header to be sent in the API call HTTP request.
	 * 	                                   Some APIs require that a certain value be sent to specify
	 * 	                                   which version of the API is being called. The default value is '*&#47;*'.
	 * 	        'accept_language'        : value of the Accept-Language HTTP header to be sent in the API call HTTP request.
	 * 	                                   Some APIs require that a certain value be sent to specify
	 * 	                                   which version of the API is being called.
	 * 	        'convert_json_to_array'  : boolean option that determines if objects should be converted into arrays when the
	 * 	                                   response is returned in JSON format. The default value is false.
	 * 	        'decode_xml_response'    : name of the method to decode XML responses. Currently only 'simplexml' is supported. It makes a
	 * 	                                   XML response be parsed and returned as a SimpleXMLElement object.
	 * 	        'fail_on_access_error'   : boolean option that determines if this functions should fail when the provider
	 * 	                                   response status is not between 200 and 299. The default value is false.
	 * 	        'files'                  : associative array with details of the parameters that must be passed as file uploads.
	 * 	                                   The array indexes must have the same name of the parameters
	 * 	                                   to be sent as files. The respective array entry values must
	 * 	                                   also be associative arrays with the parameters for each file.
	 * 	                                   Currently it supports the following parameters:
	 * 	                                   - 'type' MIME value of the content type of the file.
	 * 	                                   - 'filename' defines a custom file name for the file to be uploaded. Default: none
	 * 	                                   - 'contents' optional, the contents of the file 
	 * 	          'post_values_in_uri'   : boolean option to determine that a POST request should pass the request values in the URI. The default value is false.
	 * 	          'max_redirects'        : limit number of times that HTTP response redirects will be followed. If it is set to 0, redirection responses fail in error. The default value is 0.
	 * 	          'body'                 : request body data of a custom type. The 'request_content_type' option must be specified, so the 'body' option is considered.
	 * 	          'request_content_type' : content type that should be used to send the request values. It can be either
	 * 	                                   'application/x-www-form-urlencoded' for sending values like from Web forms, or
	 * 	                                   'application/json' for sending the values encoded in JSON format.
	 * 	                                    The default value is 'application/x-www-form-urlencoded'.
	 * 	          'headers'              : associative array of custom headers to be sent with the API call.
	 * 	                                   These headers override any values set by the class when sending the API call HTTP request.
	 * 	          'resource'             : string with a label that will be used in the error messages and debug log entries to identify what operation the request is performing.
	 * 	                                   The default value is 'API call'.
	 * 	          'response_content_type': content type that should be considered when decoding the API request response.
	 * 	                                   This overrides the Content-Type header returned by the server.
	 * 	                                   If the content type is 'application/x-www-form-urlencoded' the function will parse the data returning an array of key-value pairs.
	 * 	                                   If the content type is 'application/json' the response will be decode as a JSON-encoded data type.
	 * 	                                   Other content type values will make the function return the original response value as it was returned from the server.
	 * 	                                   The default value for this option is to use what the server returned in the Content-Type header.
	 *
	 *
	 * 	@return mixed Return the value of the API response. If the value is
	 * 	JSON encoded, this function will decode it and return the value
	 * 	converted to respective types. If the value is form encoded,
	 * 	this function will decode the response and return it as an
	 * 	array. Otherwise, the class will return the value as a string.
	 * 	This function returns false if the call was not done successfully.
	 *
	 */
	public function callAPI($url, $method, $parameters, $options);

	/**
	 * 	Returns the information about the resource owner using a
	 * 	previously obtained access token via OAuth.
	 *
	 * 	This function must be called after having
	 * 	previously obtained an access token through the OAuth protocol
	 * 	using the authenticate function, or by directly setting the variables
	 * 	access_token, as well as access_token_secret in case of using OAuth 1.0 or 1.0a services.
	 *
	 * 	@param string $endpoint URL of the user info endpoint.
	 * 	@return \eureka2\OAuth\Response\ResourceOwner The resource owner
	 */
	public function getResourceOwner($endpoint = null);

	/**
	 * 	Returns the information about the resource owner.
	 *
	 *	This function is a high-level function
	 *	that perform all the necessary actions (initalization, authentication, ...)
	 * 	before requesting the information about the resource owner.
	 *
	 * 	@param array $options array of parameters.
	 * 	@return \eureka2\OAuth\Response\ResourceOwner The resource owner
	 */
	public function fetchResourceOwner($options);

	/**
	 * 	Cleanup any resources that may have been used during the
	 * 	OAuth protocol processing or execution of API calls.
	 *
	 * 	Always call this function as the last step after calling the
	 * 	functions process or callAPI.
	 */
	public function finalize();

	/**
	 * 	Check if the access token was retrieved and if it is valid.
	 *
	 * 	Call this function when you need to check of an access token
	 * 	is valid without forcing to redirect the user to the OAuth provider
	 * 	authorization page.
	 *
	 * 	If a previously retrieved access token has expired, this function
	 * 	may renew it automatically.
	 *
	 * 	@param string $redirectUrl
	 *
	 * 	@return string|bool  the URL of the OAuth provider authorization to
	 * 	redirect the user if the access token was not yet retrieved or is not valid.
	 * 	This function returns true if the OAuth protocol was checked without errors.
	 *
	 */
	public function checkAccessToken(&$redirectUrl);

	/**
	 * 	Reset the access token to a state back when the user has
	 * 	not yet authorized the access to the OAuth server API.
	 *
	 * 	Call this function if for some reason the token to access
	 * 	the API was revoked and you need to ask the user to authorize
	 * 	the access again.
	 *
	 * 	By default the class stores and retrieves access tokens in a
	 * 	session variable named 'OAUTH_ACCESS_TOKEN'.
	 *
	 * 	This function must be called when the user is accessing your site
	 * 	pages, so it can reset the information stored in session variables
	 * 	that cache the state of a previously retrieved access token.
	 *
	 * 	Actual implementations should create a sub-class and override this
	 * 	function to reset the access token state when it is stored in
	 * 	other types of containers, like for instance databases.
	 *
	 * 	@return bool This function should return true if the access token was resetted successfully.
	 *
	 */
	public function resetAccessToken();

	/**
	 * 	Revoke a previously obtained token so it becomes invalid.
	 *
	 * 	Call this function when you need to invalidate a token that
	 * 	you no longer need to use, so it is not used by any other
	 * 	application.
	 *
	 * 	@param string $tokenTypeHint the type of token to be revoked if it is not an access token.
	 * 	@return bool This function returns true if the OAuth protocol was revoked without errors.
	 */
	public function revokeToken($tokenTypeHint = 'access_token');


	/**
	 * 	Determines whether the logOut function can be called.
	 *
	 * 	@return bool returns true if OAuth provider has a end-session endpoint
	 * 	and there is a valid access token.
	 */
	public function canLogOut();

	/**
	 * Calls the end-session endpoint to notify the provider
	 * that the end-user has logged out of the relying party site.
	 *
	 * @param string $redirect URL to which the RP is requesting that the End-User's User Agent
	 * be redirected after a logout has been performed. The value MUST have been previously
	 * registered with the OP. Value can be null.
	 *
	 * @throws OAuthClientException
	 */
	public function logOut($redirect = null);

	/**
	 *
	 * 	Determine if the current script should be exited.
	 * 	Call this function after calling the
	 * 	authenticate function and exit your script
	 * 	immediately if this function returns true.
	 *
	 */
	public function shouldExit();

	/**
	 *
	 * 	Returns the obtained access token upon
	 * 	successful OAuth authentication.
	 *
	 */
	public function getAccessToken();

	/**
	 *
	 * 	Returns the obtained refresh token upon
	 * 	successful OAuth authentication.
	 *
	 */
	public function getRefreshToken();

	/**
	 *
	 * 	Returns the obtained ID token upon
	 * 	successful OpenID authentication.
	 *
	 */
	public function getIdToken();

	/**
	 *
	 * 	Returns the current instance
	 * 	of the OAuthProvider class.
	 *
	 */
	public function getProvider();


}

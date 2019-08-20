<?php declare(strict_types = 1);

namespace eureka2\OAuth\Storage;

interface TokenStorageInterface {

	/**
	 * 	Store the values of the access token when it is succefully
	 * 	retrieved from the OAuth server.
	 *
	 * 	This method is meant to be only be called from inside the class.
	 *
	 * 	Actual implementations should create a sub-class and override this
	 * 	function to make the access token values be stored in other types
	 * 	of containers, like for instance databases.
	 *
	 * 	@param array $accessToken Associative array with properties of the access token. 
	 * 	The array may have set the following properties:
	 * 	'value': string value of the access token
	 * 	'authorized': boolean value that determines if the access token was obtained successfully
	 * 	'expiry': (optional) timestamp in ISO format relative to UTC time zone of the access token expiry time
	 * 	'type': (optional) type of OAuth token that may determine how it should be used when sending API call requests.
	 * 	'refresh': (optional) token that some servers may set to allowing refreshing access tokens when they expire.
	 *
	 * 	@return bool This function should return true if the access token was stored successfully.
	 */
	public function storeAccessToken($accessToken);

	/**
	 * 	Retrieve the OAuth access token if it was already previously stored by the
	 * 	storeAccessToken method.
	 *
	 * 	This method is meant to be only be called from inside the class.
	 *
	 * 	Actual implementations should create a sub-class and override this
	 * 	method to retrieve the access token values from other types of
	 * 	containers, like for instance databases.
	 *
	 * 	@return array|bool the properties of the access token in an
	 * 	associative array. If the access token was not yet stored, it
	 * 	returns an empty array. Otherwise, the properties it may return
	 * 	are the same that may be passed to the storeAccessToken.
	 * 	This function should return true if the access token was retrieved successfully.
	 *
	 */
	public function getStoredAccessToken();

	/**
	 * 	Reset the access token to a state back when the user has
	 * 	not yet authorized the access to the OAuth server API.
	 *
	 * 	Call this method if for some reason the token to access
	 * 	the API was revoked and you need to ask the user to authorize
	 * 	the access again.
	 *
	 * 	This method must be called when the user is accessing your site
	 * 	pages, so it can reset the information stored in session variables
	 * 	that cache the state of a previously retrieved access token.
	 *
	 * 	Actual implementations should create a sub-class and override this
	 * 	method to reset the access token state when it is stored in
	 * 	other types of containers, like for instance databases.
	 *
	 * 	@return bool This function should return true if the access token was resetted successfully.
	 *
	 */
	public function resetAccessToken();

	public function getStoredState();

	public function getStoredNonce();
	
	public function storeUser($user);

	public function getStoredUser();

	public function initialize();

	public function finalize();

}

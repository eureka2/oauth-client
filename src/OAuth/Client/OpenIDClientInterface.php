<?php

namespace eureka2\OAuth\Client;
 
interface OpenIDClientInterface extends OAuthClientInterface{

	/**
	 *
	 * 	Determines the active state of a token
	 *	and the meta-information about this token.
	 *
	 * @param string $token The string value of the token to introspect.
	 * This is the "access_token" or the "refresh_token"  value returned from the token endpoint.
	 *
	 * @param string $tokenTypeHint hint about the type of the submitted token.
	 * Values  are 'access_token' or 'refresh_token'.
	 * if omitted the server will use heuristics to determine the token type
	 *
	 * @return object|false The Json object containing the state and meta-information about the token
	 * or false if this information can not be obtained
	 *
	 * @throws \eureka2\OAuth\Exception\OAuthClientException
	 */
	public function introspectToken($token, $tokenTypeHint = '');


}

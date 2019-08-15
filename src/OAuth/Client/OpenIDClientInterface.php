<?php

namespace eureka2\OAuth\Client;
 
interface OpenIDClientInterface extends OAuthClientInterface{

	/**
	 *
	 * 	Determines the active state of a token
	 *	and the meta-information about this token.
	 *
	 */
	public function introspectToken($token, $tokenTypeHint = '');


}

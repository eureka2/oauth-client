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

/**
 *
 * This interface completes the OAuthClient interface for the OpenID protocol.
 *
 */
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
	public function introspectToken(string $token, string $tokenTypeHint = '');


}

<?php

namespace eureka2\OAuth\Storage;

interface TokenStorageManagementInterface {

	/**
	 * Creates and saves a new OAuth session
	 *
	 * @param \eureka2\OAuth\Storage\OAuthSessionValue|null $session The variable receiving information about the new session
	 * @return bool  true if the session is created, false if not
	 */
	public function createOAuthSession(&$session);

	/**
	 * Retrieves an OAuth session for a given provider
	 *
	 * @param string $sessionId The id of the session
	 * @param string $provider The provider
	 * @param \eureka2\OAuth\Storage\OAuthSessionValue|null $oauthSession The variable receiving information about the session
	 * @return bool 
	 */
	public function getOAuthSession($sessionId, $provider, &$oauthSession);

	/**
	 * Saves a session for later use
	 *
	 * @param \eureka2\OAuth\Storage\OAuthSessionValue $session The information about the session 
	 * @return bool true if the session is successfully saved, false otherwise
	 */
	public function saveOAuthSession($session);

}

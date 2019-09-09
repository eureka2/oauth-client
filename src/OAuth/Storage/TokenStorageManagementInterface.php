<?php declare(strict_types = 1);

/*
 * This file is part of the eureka2/oauth-client library.
 *
 * Copyright (c) 2019 Jacques Archimède
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace eureka2\OAuth\Storage;

interface TokenStorageManagementInterface {

	/**
	 * Creates and saves a new OAuth session
	 *
	 * @param \eureka2\OAuth\Storage\OAuthSession|null $session The variable receiving information about the new session
	 * @return bool  true if the session is created, false if not
	 */
	public function createOAuthSession(&$session);

	/**
	 * Retrieves an OAuth session for a given provider
	 *
	 * @param string $sessionId The id of the session
	 * @param string $provider The provider
	 * @param \eureka2\OAuth\Storage\OAuthSession|null $oauthSession The variable receiving information about the session
	 * @return bool 
	 */
	public function getOAuthSession($sessionId, $provider, &$oauthSession);

	/**
	 * Saves a session for later use
	 *
	 * @param \eureka2\OAuth\Storage\OAuthSession $session The information about the session 
	 * @return bool true if the session is successfully saved, false otherwise
	 */
	public function saveOAuthSession($session);

}

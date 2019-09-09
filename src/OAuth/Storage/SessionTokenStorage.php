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

use eureka2\OAuth\Exception\OAuthClientPHPException;

/**
 *
 * This class uses the superglobal $_SESSION
 * to store the OAuth session variables. 
 *
 * This class is instantiated if the 'storage' option is set as follows:
 * 'storage' => [
 *    'type' => 'session'
 * ]
 *
 */
class SessionTokenStorage
	extends AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	/**
	 * {@inheritdoc}
	 */
	public function createOAuthSession(&$session) {
		$session = $this->initializeOAuthSession();
		$this->startSession();
		return $this->saveOAuthSession($session);
	}

	/**
	 * {@inheritdoc}
	 */
	public function getOAuthSession($sessionId, $provider, &$oauthSession) {
		$this->startSession();
		if (!isset($_SESSION[$provider]) || !isset($_SESSION[$provider]['OAUTH_SESSION'])) {
			$oauthSession = null;
			return true;
		}
		$oauthSession = $_SESSION[$provider]['OAUTH_SESSION'];
		if ($oauthSession->getSessionId() != $sessionId) {
			$oauthSession = null;
		}
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function saveOAuthSession($session) {
		$_SESSION[$session->getProvider()]['OAUTH_SESSION'] = $session;
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function resetAccessToken() {
		$provider = $this->client->getProvider()->getName();
		$this->client->trace('Resetting the access token status for OAuth provider ' . $provider);
		$this->startSession();
		unset($_SESSION[$provider]);
		$this->deleteSessionCookie();
		$this->removeProviderFromCookie();
		return true;
	}

	/**
	 * Starts a PHP session, if not already started
	 */
	private function startSession() {
		if (session_id() === '' && !session_start()) {
			throw new OAuthClientPHPException('it was not possible to start the PHP session');
		}
	}

}

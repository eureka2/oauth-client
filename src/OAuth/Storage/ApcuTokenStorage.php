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

/**
 *
 * This class uses the PHP APC User Cache (APCu) 
 * to store the OAuth session variables. 
 *
 * This class is instantiated if the 'storage' option is set as follows:
 * 'storage' => [
 *    'type' => 'apcu'
 * ]
 *
 */
class ApcuTokenStorage
	extends AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	/**
	 * {@inheritdoc}
	 */
	public function createOAuthSession(&$session) {
		$session = $this->initializeOAuthSession();
		apcu_add($session->getSessionId(), $session);
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function getOAuthSession($sessionId, $provider, &$oauthSession) {
		if (empty($this->getSessionCookie()) || !apcu_exists($this->getSessionCookie())) {
			$oauthSession = null;
			return true;
		}
		$oauthSession = apcu_fetch($this->getSessionCookie());
		if ($oauthSession->getSessionId() != $sessionId) {
			$oauthSession = null;
		}
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function saveOAuthSession($session) {
		apcu_store($this->getSessionCookie(), $session);
		return true;
	}

	/**
	 * {@inheritdoc}
	 */
	public function resetAccessToken() {
		$provider = $this->client->getProvider()->getName();
		$this->client->trace('Resetting the access token status for OAuth provider ' . $provider);
		apcu_delete($this->getSessionCookie());
		$this->deleteSessionCookie();
		$this->removeProviderFromCookie();
		return true;
	}

}

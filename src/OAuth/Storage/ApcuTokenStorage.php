<?php

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Exception\OAuthClientPHPException;

class ApcuTokenStorage
	extends AbstractTokenStorage
	implements TokenStorageInterface, TokenStorageManagementInterface {

	public function createOAuthSession(&$session) {
		$session = null;
		$this->initializeOAuthSession($session);
		apcu_add($session->getSessionId(), $session);
		return true;
	}

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

	public function saveOAuthSession($session) {
		apcu_store($this->getSessionCookie(), $session);
		return true;
	}

	public function resetAccessToken() {
		$provider = $this->client->getProvider()->getName();
		$this->client->trace('Resetting the access token status for OAuth provider ' . $provider);
		apcu_delete($this->getSessionCookie());
		$this->deleteSessionCookie();
		return true;
	}

}

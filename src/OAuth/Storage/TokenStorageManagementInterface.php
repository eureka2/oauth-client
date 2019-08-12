<?php

namespace eureka2\OAuth\Storage;

interface TokenStorageManagementInterface {

	public function createOAuthSession(&$session);

	public function getOAuthSession($sessionId, $provider, &$oauthSession);

	public function saveOAuthSession($session);

}

<?php require('../../vendor/autoload.php');

use eureka2\OAuth\Client\OAuthClientFactory;
use eureka2\OAuth\Exception\OAuthClientAccessTokenException;
use eureka2\OAuth\Exception\OAuthClientAuthorizationException;
use eureka2\OAuth\Exception\OAuthClientException;
use eureka2\OAuth\Exception\OAuthClientPHPException;

include 'display-results-inc.php';

try {
	$client = OAuthClientFactory::create('Google');
	$client->setDebug(false);
	$client->setDebugHttp(true);

	$client->setRedirectUri('http://' . $_SERVER['HTTP_HOST'] .
			dirname(strtok($_SERVER['REQUEST_URI'], '?')) . '/google.php');

	// see http://code.google.com/apis/console
	$client->setClientId('');
	$client->setClientSecret('');

	$user = (object) [];
	if ($client->initialize([
			'strategy' => [
				'offline' => true,
				'scope' => 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile'
			]
		])) {
		if ($client->authenticate()) {
			if (!empty($client->getAccessToken())) {
				$user = $client->callAPI(
					'https://www.googleapis.com/oauth2/v1/userinfo',
					'GET', [], ['fail_on_access_error' => true]
				);
			}
		}
		$client->finalize();
	}
	if ($client->shouldExit()) {
		exit;
	}
	connected('Google', $user, '../logout/google.php');
} catch (OAuthClientAccessTokenException $e) {
	failed('OAuth access token error', $e->getMessage());
} catch (OAuthClientAuthorizationException $e) {
	failed('OAuth authorization error', $e->getMessage());
} catch (OAuthClientPHPException $e) {
	failed('OAuth PHP error', $e->getMessage());
} catch (OAuthClientException $e) {
	failed('OAuth client error', $e->getMessage());
} catch (Exception $e) {
	failed('OAuth error', $e->getMessage());
}


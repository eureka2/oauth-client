<?php require('../../vendor/autoload.php');

use eureka2\OAuth\Client\OAuthClient;
use eureka2\OAuth\Exception\OAuthClientAccessTokenException;
use eureka2\OAuth\Exception\OAuthClientAuthorizationException;
use eureka2\OAuth\Exception\OAuthClientException;
use eureka2\OAuth\Exception\OAuthClientPHPException;

include 'display-results-inc.php';

try {
	$client = OAuthClient::create('Google');
	$client->setDebug(false);
	$client->setDebugHttp(true);

	$user = $client->fetchResourceOwner([
		'provider' => [
			'registration' => [
				'keys' => [
					'client_id' => '',
					'client_secret' => '',
					'redirect_uri' => 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']
				]
			]
		],
		'strategy' => [
			'offline_access' => true
		]
	]);
	connected('Google', $user, '../logout/google.php');
} catch (OAuthClientAccessTokenException $e) {
	failed('OAuth access token error', $e->getMessage());
} catch (OAuthClientAuthorizationException $e) {
	failed('OAuth authorization error', $e->getMessage());
} catch (OAuthClientPHPException $e) {
	failed('OAuth PHP error', $e->getMessage());
} catch (OAuthClientException $e) {
	failed('OAuth client error', $e->getMessage());
} catch (\Exception $e) {
	failed('OAuth error', $e->getMessage());
}


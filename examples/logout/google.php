<?php require('../../vendor/autoload.php');

use eureka2\OAuth\Client\OAuthClient;
use eureka2\OAuth\Exception\OAuthClientAccessTokenException;
use eureka2\OAuth\Exception\OAuthClientAuthorizationException;
use eureka2\OAuth\Exception\OAuthClientException;
use eureka2\OAuth\Exception\OAuthClientPHPException;
use eureka2\Sasl\SaslClientException;

try {
	$client = OAuthClient::create('Google');
	$client->setDebug(false);
	$client->setDebugHttp(true);

	$client->setClientId('');
	$client->setClientSecret('');

	$valid_token = false;
	if ($client->initialize()) {
		if ($client->canLogOut()) {
			$client->logOut('http://' . $_SERVER['HTTP_HOST'] .
			dirname(dirname(strtok($_SERVER['REQUEST_URI'], '?'))) . '/index.php');
		} elseif ($client->canRevokeToken()) {
			$valid_token = $client->revokeToken();
		}
		$client->finalize();
	}
	if ($client->shouldExit()) {
		exit;
	}
	disconnected($valid_token);
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

function disconnected($valid_token) {
	?>
	<!DOCTYPE html>
	<html>
		<head>
			<title>Google OAuth Client Revoke Token</title>
		</head>
		<body>
			<?php
			if ($valid_token)
				echo '<h1>You are logged out: The OAuth access token was revoked successfully!</h1>';
			else
				echo '<h1>You were not logged in: There is no valid access token to revoke!</h1>';
			?>
		</body>
	</html>
	<?php
}

function failed($title, $message) {
	?>
	<!DOCTYPE html>
	<html>
		<head>
			<title<?php echo htmlspecialchars($title); ?></title>
		</head>
		<body>
			<h1><?php echo htmlspecialchars($title); ?></h1>
			<pre>Error: <?php echo htmlspecialchars($message); ?></pre>
		</body>
	</html>
	<?php
}
?>
<?php

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Exception\OAuthClientException;

class TokenStorageFactory {

	public static function create($client, $storage = [ 'type' => 'session']) {
		if (!isset($storage['type'])) {
			throw new OAuthClientException('The token storage type is required');
		}
		$type = $storage['type'];
		unset($storage['type']);
		switch ($type) {
			case 'session':
				return new SessionTokenStorage($client);
			case 'cookie':
				return new CookieTokenStorage($client, $storage);
			case 'pdo':
			case 'database':
				return new PdoTokenStorage($client, $storage);
			case 'filesystem':
				return new FilesystemTokenStorage($client, $storage);
				break;
			default:
				throw new OAuthClientException(
					sprintf(
						'The token storage %s is not supported' ,
						$storage['type']
					)
				);
		}
	}
}

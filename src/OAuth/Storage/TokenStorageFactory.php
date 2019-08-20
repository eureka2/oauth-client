<?php declare(strict_types = 1);

namespace eureka2\OAuth\Storage;

use eureka2\OAuth\Exception\OAuthClientException;

class TokenStorageFactory {

	/**
	 * Create a Token Storage instance according to the given storage options.
	 *
	 * @param \eureka2\OAuth\Client\OAuthClientInterface $client
	 * @param array $storage the storage options
	 *
	 * @return \eureka2\OAuth\Storage\TokenStorageInterface
	 */
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
			case 'apcu':
				if (function_exists('apcu_store')) {
					return new ApcuTokenStorage($client);
				}
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

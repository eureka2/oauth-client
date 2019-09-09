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

use eureka2\OAuth\Exception\OAuthClientException;

class TokenStorage {

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
		switch ($storage['type']) {
			case 'session':
				return new SessionTokenStorage($client, $storage);
			case 'cookie':
				return new CookieTokenStorage($client, $storage);
			case 'pdo':
			case 'database':
				return new PdoTokenStorage($client, $storage);
			case 'apcu':
				if (function_exists('apcu_store')) {
					return new ApcuTokenStorage($client, $storage);
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

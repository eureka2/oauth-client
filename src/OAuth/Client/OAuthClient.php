<?php declare(strict_types = 1);

/*
 * This file is part of the eureka2/oauth-client library.
 *
 * Copyright (c) 2019 Jacques Archimède
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Client\OAuthClient;
use eureka2\OAuth\Exception\OAuthClientException;
use eureka2\OAuth\Provider\OAuthBuiltinProviders;

/**
 * This class provides a factory method for creating an OAuth client instance
 * based on the provider name, protocol, and version of this protocol.
 *
 * If the provider is not a buit-in provider, protocol and version are required.
 *
 * It also provides a static function to find the last resource owner who logged in.
 */
class OAuthClient {

	/**
	 * Creates a OAuth client instance according to the given parameters.
	 *
	 * @param string $provider the provider's name
	 * @param string $protocol protocol name among 'oauth' or 'openid'
	 * @param string $version protocol version among '1.0', '1.0a' or '2.0'
	 *
	 * @throws \eureka2\OAuth\Exception\OAuthClientException if an error occurs
	 */
	public static function create($provider, $protocol = null, $version = null) {
		if (isset(OAuthBuiltinProviders::PROVIDERS[$provider])) {
			$pprotocol = OAuthBuiltinProviders::PROVIDERS[$provider]['protocol']['name'];
			if ($protocol === null) {
				$protocol = $pprotocol;
			} elseif ($protocol != $pprotocol) {
				throw new OAuthClientException(
					sprintf(
						"The OAuth '%s' protocol doesn't match the one registered for the '%s' provider",
						$protocol, $provider
					)
				);
			}
			$pversion = OAuthBuiltinProviders::PROVIDERS[$provider]['protocol']['version'];
			if ($version === null) {
				$version = $pversion;
			} elseif ($version != $pversion) {
				throw new OAuthClientException(
					sprintf(
						"The OAuth '%s' version doesn't match the one registered for the '%s' provider",
						$version, $provider
					)
				);
			}
		}
		switch (strtolower($protocol)) {
			case 'openid':
				return new OpenIDClient($provider);
			case 'oauth':
				$version = $version ?? '2.0';
				switch ($version) {
					case '1.0':
					case '1.0a':
						return new OAuth1Client($provider);
					case '2.0':
						return new OAuth2Client($provider);
					default:
						throw new OAuthClientException(
							sprintf(
								"The OAuth version '%s' is not supported" ,
								$version
							)
						);
				}
			default:
				throw new OAuthClientException(
					sprintf(
						"The protocol '%s' is not supported" ,
						$protocol
					)
				);
		}
	}

	/**
	 * Returns the last connected resource owner if there is one.
	 *
	 * @return \eureka2\OAuth\Response\ResourceOwner|null
	 */
	public static function getConnectedResourceOwner() {
		$providers_conf = $_COOKIE['oauth_client_providers'] ?? '';
		$providers_conf = unserialize(base64_decode($providers_conf));
		if (!is_array($providers_conf)) {
			$providers_conf = [];
		}
		$providers = array_reverse(array_keys($providers_conf));
		$user = null;
		foreach ($providers as $provider) {
			try {
				$client = OAuthClient::create($provider);
				if ($client->initialize($providers_conf[$provider])) {
					if ($client->isAuthenticated() && !empty($client->getAccessToken())) {
						$user = $client->getResourceOwner();
						$client->finalize();
						break;
					}
					$client->finalize();
				}
			} catch (\Exception $e){
			}
		}
		return $user;
	}

}

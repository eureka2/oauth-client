<?php

namespace eureka2\OAuth\Client;

use eureka2\OAuth\Exception\OAuthClientException;

class OAuthClientFactory {

	public static function create($provider, $version = null) {
		if (isset(OAuthBuiltinProviders::PROVIDERS[$provider])) {
			$pversion = OAuthBuiltinProviders::PROVIDERS[$provider]['configuration']['oauth_version'];
			if ($version === null) {
				$version = $pversion;
			} elseif ($version != $pversion) {
				throw new OAuthClientException(
					sprintf(
						"The OAuth '%s' version doesn't match the one registered for the '%s' provider",
						$version,
						$provider
					)
				);
			}
		}
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
	}
}

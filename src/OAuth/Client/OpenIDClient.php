<?php

namespace eureka2\OAuth\Client;

class OpenIDClient extends OAuth2Client
	implements OAuthClientInterface, OpenIDClientInterface {

	protected function discover($discoveryEndpoint) {
		$url = $discoveryEndpoint . '/.well-known/openid-configuration';
		$options = [
			'resource' => 'Openid configuration',
			'accept' => 'application/json'
		];
		$response = $this->sendOAuthRequest($url, 'GET', [], $options);
		if ($response === false || isset($response->error)) {
			throw new OAuthClientException(
				sprintf(
					"Can't discover the openid configuration at %s, reason : %s",
					$discoveryEndpoint,
					$response->error ?? 'send request error'
				)
			);
		}
		$configuration = [
			'protocol' => 'openid',
			'version' => '1.0',
			'authorization_endpoint' => $response->authorization_endpoint . '?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
			'token_endpoint' => $response->token_endpoint,
			'discovery_endpoint' => $discoveryEndpoint,
			'registration_endpoint' => $response->registration_endpoint ?? '',
			'introspection_endpoint' => $response->introspection_endpoint ?? '',
			'revocation_endpoint' => $response->revocation_endpoint ?? '',
			'userinfo_endpoint' => $response->userinfo_endpoint ?? '',
			'end_session_endpoint' => $response->end_session_endpoint ?? '',
			'jwks_uri' => $response->jwks_uri ?? '',
			'scopes_supported' => $response->scopes_supported ?? [],
			'response_types_supported' => $response->response_types_supported ?? [],
			'response_modes_supported' => $response->response_modes_supported ?? [],
			'token_endpoint_auth_methods_supported' => $response->token_endpoint_auth_methods_supported ?? [],
			'subject_types_supported' => $response->subject_types_supported ?? [],
			'id_token_signing_alg_values_supported' => $response->id_token_signing_alg_values_supported ?? [],
			'claims_supported' => $response->claims_supported ?? []
		];
		return $configuration;
	}

	/**
	 * @inheritdoc
	 */
	public function introspectToken($token, $tokenTypeHint = '') {
		$endpoint = $this->provider->getIntrospectionEndpoint();
		if (empty($endpoint)) {
			return false;
		}
		$parameters = [
			'token' => $token,
		];
		if (!empty($tokenTypeHint)) {
			$parameters['token_type_hint'] = $tokenTypeHint;
		}
		$clientId = $this->provider->getClientId();
		$clientSecret = $this->provider->getClientSecret();
		$parameters = http_build_query($parameters, null, '&');
		$options = [
			'resource' => 'OAuth introspect Token',
			'accept' => 'application/json',
			'headers' => [
				'Authorization: Basic ' . base64_encode($clientId . ':' . $clientSecret)
			]
		];
		return $this->sendOAuthRequest($endpoint, 'POST', $parameters, $options);
	}

}

<?php

namespace eureka2\OAuth\Client;

class OAuthBuiltinProviders {

	const PROVIDERS = [
		'Facebook' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://www.facebook.com/dialog/oauth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://graph.facebook.com/oauth/access_token'
			],
			'strategy' => [
				'reauthentication_parameter' => 'auth_type=reauthenticate'
			]
		],
		'github' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://github.com/login/oauth/access_token',
				'userinfo_endpoint' => 'https://api.github.com/user',
				'user_id_field' => 'id'
			],
			'strategy' => [
				'access_token_content_type' => 'application/json'
			]
		],
		'Gitlab' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://gitlab.com/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://gitlab.com/oauth/token',
				'jwks_uri' => 'https://gitlab.com/oauth/discovery/keys'
			],
			'strategy' => [
			]
		],
		'Google' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://accounts.google.com/o/oauth2/token',
				'revocation_endpoint' => 'https://accounts.google.com/o/oauth2/revoke',
				'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs'
			],
			'strategy' => [
				'offline_access_parameter' => 'access_type=offline&approval_prompt=force'
			]
		],
		"Google1" => [
			'configuration' => [
				"oauth_version" => "1.0a",
				"authorization_endpoint" => "https://www.google.com/accounts/OAuthAuthorizeToken",
				"token_endpoint" => "https://www.google.com/accounts/OAuthGetAccessToken",
				"request_token_endpoint" => "https://www.google.com/accounts/OAuthGetRequestToken?scope={SCOPE}"
			]
		],
		'franceconnect' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}&nonce={NONCE}',
				'token_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/token',
				'end_session_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/logout',
				'userinfo_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/userinfo?schema=openid'

			],
			'strategy' => [
				'offline_access_parameter' => 'access_type=offline&approval_prompt=force'
			]
		],
		'franceconnectSandbox' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}&nonce={NONCE}',
				'token_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/token',
				'end_session_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/logout',
				'userinfo_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo?schema=openid'

			],
			'strategy' => [
				'offline_access_parameter' => 'access_type=offline&approval_prompt=force'
			]
		],
		'LinkedIn' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://www.linkedin.com/oauth/v2/authorization?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&response_type=code&state={STATE}',
				'token_endpoint' => 'https://www.linkedin.com/oauth/v2/accessToken'
			],
			'strategy' => [
				'default_access_token_type' => 'Bearer'
			]
		],
		'Microsoft' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://login.live.com/oauth20_authorize.srf?client_id={CLIENT_ID}&scope={SCOPE}&response_type=code&redirect_uri={REDIRECT_URI}&state={STATE}',
				'token_endpoint' => 'https://login.live.com/oauth20_token.srf',
				'revocation_endpoint' => 'https://login.microsoftonline.com/common/oauth2/logout',
				'jwks_uri' => 'https://login.microsoftonline.com/consumers/discovery/v2.0/keys'
			],
			'strategy' => [
			]
		],
		'Orange' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://api.orange.com/openidconnect/fr/v1/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&response_type=code&state={STATE}',
				'token_endpoint' => 'https://api.orange.com/oauth/v2/token'
			],
			'strategy' => [
			]
		],
		'Paypal' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&state={STATE}&scope={SCOPE}',
				'token_endpoint' => 'https://api.paypal.com/v1/identity/openidconnect/tokenservice'
			],
			'strategy' => [
			]
		],
		'PaypalSandbox' => [
			'configuration' => [
				'oauth_version' => '2.0',
				'authorization_endpoint' => 'https://www.sandbox.paypal.com/signin/authorize?flowEntry=static&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&state={STATE}&scope={SCOPE}',
				'token_endpoint' => 'https://api.sandbox.paypal.com/v1/oauth2/token'
			],
			'strategy' => [
				'access_token_content_type' => 'application/json',
				'grant_type' => 'authorization_code',
				'access_token_authentication' => 'basic',
				'access_token_language' => 'fr-FR'
			]
		],
		'Twitter' => [
			'configuration' => [
				'oauth_version' => '1.0a',
				'authorization_endpoint' => 'https://api.twitter.com/oauth/authenticate',
				'request_token_endpoint' => 'https://api.twitter.com/oauth/request_token',
				'token_endpoint' => 'https://api.twitter.com/oauth/access_token'
			],
			'strategy' => [
				'url_parameters' => false
			]
		],
		'Yahoo' => [
			'configuration' => [
				'oauth_version' => '1.0a',
				'authorization_endpoint' => 'https://api.login.yahoo.com/oauth/v2/request_auth',
				'request_token_endpoint' => 'https://api.login.yahoo.com/oauth/v2/get_request_token',
				'token_endpoint' => 'https://api.login.yahoo.com/oauth/v2/get_token'
			],
			'strategy' => [
				'authorization_header' => false
			]
		]
	];

}

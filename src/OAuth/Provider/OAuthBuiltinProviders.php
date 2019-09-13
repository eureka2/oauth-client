<?php declare(strict_types = 1);

/*
 * This file is part of the eureka2/oauth-client library.
 *
 * Copyright (c) 2019 Jacques Archimède
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace eureka2\OAuth\Provider;

/**
 * This class contains the configuration for the following OAuth providers:
 * 
 * - Facebook (Oauth 2.0)
 * - Github (Oauth 2.0)
 * - Gitlab (OpenID 1.0)
 * - Google (Oauth 2.0)
 * - Google1 ( OAuth 1.0a)
 * - Franceconnect (Oauth 2.0)
 * - FranceconnectSandbox (Oauth 2.0)
 * - LinkedIn (Oauth 2.0)
 * - Microsoft (OpenID 1.0)
 * - Orange  (Oauth 2.0)
 * - Paypal (Oauth 2.0)
 * - PaypalSandbox (Oauth 2.0)
 * - Twitter (Oauth 1.0a)
 * - Yahoo (Oauth 1.0a)
 *
 */
class OAuthBuiltinProviders {

	const PROVIDERS = [
		'Facebook' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://www.facebook.com/dialog/oauth?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://graph.facebook.com/oauth/access_token',
				'userinfo_endpoint' => 'https://graph.facebook.com/v2.3/me?fields=id,first_name,gender,last_name,link,locale,name,timezone,updated_time,verified,email'
			],
			'mapping' => [
				'user_id_field' => 'id',
				'given_name_field' => 'first_name',
				'family_name_field' => 'last_name'
			],
			'strategy' => [
				'scope' => 'public_profile,email,user_gender',
				'reauthentication_parameter' => 'auth_type=reauthenticate'
			]
		],
		'Github' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://github.com/login/oauth/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://github.com/login/oauth/access_token',
				'userinfo_endpoint' => 'https://api.github.com/user'
			],
			'mapping' => [
				'user_id_field' => 'id',
				'picture_field' => 'avatar_url',
				'website_field' => 'html_url'
			],
			'strategy' => [
				'scope' => 'openid read:user',
				'access_token_content_type' => 'application/json'
			]
		],
		'Gitlab' => [
			'protocol' => [
				'name' => 'openid',
				'version' => '1.0'
			],
			'endpoints' => [
				'discovery_endpoint' => 'https://gitlab.com',
				'userinfo_endpoint' => 'https://gitlab.com/api/v4/user'

			],
			'mapping' => [
				'picture_field' => 'avatar_url'
			],
			'strategy' => [
				'scope' => 'openid read_user'
			]
		],
		'Google' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}',
				'token_endpoint' => 'https://accounts.google.com/o/oauth2/token',
				'revocation_endpoint' => 'https://accounts.google.com/o/oauth2/revoke',
				'userinfo_endpoint' => 'https://www.googleapis.com/oauth2/v1/userinfo',
				'jwks_uri' => 'https://www.googleapis.com/oauth2/v3/certs'
			],
			'strategy' => [
				'scope' => 'openid profile email',
				'offline_access_parameter' => 'access_type=offline&approval_prompt=force'
			]
		],
		"Google1" => [
			'protocol' => [
				'name' => 'oauth',
				"version" => "1.0a"
			],
			'endpoints' => [
				"authorization_endpoint" => "https://www.google.com/accounts/OAuthAuthorizeToken",
				"token_endpoint" => "https://www.google.com/accounts/OAuthGetAccessToken",
				"request_token_endpoint" => "https://www.google.com/accounts/OAuthGetRequestToken?scope={SCOPE}"
			]
		],
		'Franceconnect' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}&nonce={NONCE}',
				'token_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/token',
				'end_session_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/logout',
				'userinfo_endpoint' => 'https://app.franceconnect.gouv.fr/api/v1/userinfo?schema=openid'
			],
			'strategy' => [
				'scope' => 'openid identite_pivot address email phone',
				'offline_access' => true
			]
		],
		'FranceconnectSandbox' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/authorize?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&state={STATE}&nonce={NONCE}',
				'token_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/token',
				'end_session_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/logout',
				'userinfo_endpoint' => 'https://fcp.integ01.dev-franceconnect.fr/api/v1/userinfo?schema=openid'
			],
			'strategy' => [
				'scope' => 'openid identite_pivot address email phone',
				'offline_access' => true
			]
		],
		'LinkedIn' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://www.linkedin.com/oauth/v2/authorization?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&response_type=code&state={STATE}',
				'token_endpoint' => 'https://www.linkedin.com/oauth/v2/accessToken'
			],
			'strategy' => [
				'default_access_token_type' => 'Bearer'
			]
		],
		'Microsoft' => [
			'protocol' => [
				'name' => 'openid',
				'version' => '1.0'
			],
			'endpoints' => [
				'discovery_endpoint' => 'https://login.microsoftonline.com/common/v2.0',
				'userinfo_endpoint' => 'https://apis.live.net/v5.0/me'
			],
			'mapping' => [
				'given_name_field' => 'first_name',
				'family_name_field' => 'last_name',
				'email_field' => 'emails.preferred',
				'updated_at_field' => 'updated_time'
			],
			'strategy' => [
				'offline_access' => true,
				'scope' => 'openid wl.basic wl.emails'
			]
		],
		'Orange' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://api.orange.com/openidconnect/fr/v1/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope={SCOPE}&response_type=code&state={STATE}',
				// 'token_endpoint' => 'https://api.orange.com/oauth/v2/token',
				'token_endpoint' => 'https://api.orange.com/openidconnect/fr/v1/token',
				// 'userinfo_endpoint' => 'https://api.orange.com/openidconnect/v1/userinfo'
				'userinfo_endpoint' => 'https://api.orange.com/userdetails/fr/v2/userinfo'
			],
			'strategy' => [
				'scope' => 'openid profile address phone email profile_limited'
			]
		],
		'Paypal' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://www.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&state={STATE}&scope={SCOPE}',
				'token_endpoint' => 'https://api.paypal.com/v1/identity/openidconnect/tokenservice'
			],
			'strategy' => [
				'scope' => 'openid profile email address'
			]
		],
		'PaypalSandbox' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '2.0'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://www.sandbox.paypal.com/webapps/auth/protocol/openidconnect/v1/authorize?client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&response_type=code&state={STATE}&scope={SCOPE}',
				'token_endpoint' => 'https://api.sandbox.paypal.com/v1/identity/openidconnect/tokenservice',
				'userinfo_endpoint' => 'https://api.sandbox.paypal.com/v1/identity/openidconnect/userinfo?schema=openid'
			],
			'strategy' => [
				'scope' => 'openid profile email address'
			]
		],
		// 'PaypalSandbox' => [
			// 'protocol' => [
				// 'name' => 'oauth',
				// 'version' => '2.0'
			// ],
			// 'endpoints' => [
				// 'authorization_endpoint' => 'https://www.sandbox.paypal.com/connect?flowEntry=static&response_type=code&client_id={CLIENT_ID}&scope={SCOPE}&redirect_uri={REDIRECT_URI}&state={STATE}',
				// 'token_endpoint' => 'https://api.sandbox.paypal.com/v1/oauth2/token',
				// 'authorization_endpoint' => 'https://api.sandbox.paypal.com/v1/identity/oauth2/userinfo?schema=paypalv1.1'
			// ],
			// 'strategy' => [
				// 'scope' => 'openid profile email address',
				// 'access_token_content_type' => 'application/json',
				// 'grant_type' => 'authorization_code',
				// 'access_token_authentication' => 'basic',
				// 'access_token_language' => 'fr-FR'
			// ]
		// ],
		'Twitter' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '1.0a'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://api.twitter.com/oauth/authenticate',
				'request_token_endpoint' => 'https://api.twitter.com/oauth/request_token',
				'token_endpoint' => 'https://api.twitter.com/oauth/access_token'
			],
			'mapping' => [
				'user_id_field' => 'id',
				'nickname_field' => 'screen_name',
				'picture_field' => 'profile_image_url_https',
				'website_field' => 'url'
			],
			'strategy' => [
				'token_request_method' => 'POST',
				'parameters_in_url' => false
			]
		],
		'Yahoo' => [
			'protocol' => [
				'name' => 'oauth',
				'version' => '1.0a'
			],
			'endpoints' => [
				'authorization_endpoint' => 'https://api.login.yahoo.com/oauth/v2/request_auth',
				'request_token_endpoint' => 'https://api.login.yahoo.com/oauth/v2/get_request_token',
				'token_endpoint' => 'https://api.login.yahoo.com/oauth/v2/get_token'
			],
			'strategy' => [
				'authorization_in_header' => false
			]
		]
	];

}

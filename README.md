# oauth-client
OAuth client

**ATTENTION**: the developments are not finished, do not use

# Usage

## High-level request to a builtin OAuth provider
 ```php
use eureka2\OAuth\Client\OAuthClientFactory;

try {
    $client = OAuthClientFactory::create('Google');
    $user = $client->fetchResourceOwner([
        'provider' => [
            'registration' => [
                'keys' => [
                    'client_id' => '<YOUR CLIENT ID>',
                    'client_secret' => '<YOUR CLIENT SECRET>',
                    'redirect_uri' => 'http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']
                ]
            ]
        ],
        'strategy' => [
            'offline_access' => true
        ]
    ]);
    ....
    // Do something with $user
} catch (\Exception $e) {
    // Do something with $e
}
```

## Options
```php
$options = [
  'provider' => [
    'protocol' => [
      'name' => 'string',     // 'oauth' or 'openid'
      'version' => 'string'   // '1.0', '1.0a', '2.0' for 'oauth' or '1.0' for 'openid'
    ],
    'endpoints' => [
      'discovery_endpoint' => 'string',
      'authorization_endpoint' => 'string',
      'token_endpoint' => 'string',
      'registration_endpoint' => 'string',
      'introspection_endpoint' => 'string',
      'revocation_endpoint' => 'string',
      'request_token_endpoint' => 'string',
      'userinfo_endpoint' => 'string',
      'end_session_endpoint' => 'string',
      'pin_dialog_url' => 'string',
      'jwks_uri' => 'string'
    ],
    'mapping' => [
      'user_id_field' => 'string'
    ],
    'registration' => [
      'keys' => [
        'client_id' => 'string',
        'client_secret' => 'string',
        'redirect_uri' => 'string',
        'realm' => 'string',
        'api_key' => 'string',
        'pin' => 'string'
      ],
      'credentials' => [
        'oauth_username' => 'string',
        'oauth_password' => 'string'
      ]
    ]
  ],
  'strategy' => [
    'reauthentication_parameter' => 'string',
    'offline_access' => 'boolean',
    'offline_access_parameter' => 'string',
    'append_state_to_redirect_uri' => 'string',
    'authorization_header' => 'boolean',
    'url_parameters' => 'boolean',
    'token_request_method' => 'string',
    'signature_method' => 'string',              // values : 'PLAINTEXT', 'HMAC-SHA1' and 'RSA-SHA1'
    'signature_certificate_file' => 'string',
    'access_token_authentication' => 'string',
    'access_token_parameter' => 'string',
    'default_access_token_type' => 'string',
    'store_access_token_response' => 'boolean',
    'refresh_token_authentication' => 'string',
    'grant_type' => 'string',
    'get_token_with_api_key' => 'boolean',
    'access_token_content_type' => 'string',
    'access_token_language' => 'string',
    'scope' => 'string'
  ],
  'storage' => [         // token storage
     'type' => 'string', // 'session', 'cookie', 'apcu' or 'pdo' (default : 'session')
     'key' => 'string',  // if type == 'cookie'
     'dsn' => 'string'   // if type == 'pdo'
  ]
];
```
# Copyright and license

&copy; 2019 Eureka2 - Jacques Archimède. Code released under the [MIT license](https://github.com/eureka2/oauth-client/blob/master/LICENSE).

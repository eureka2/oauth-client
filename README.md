# oauth-client

This library is a multi-protocol client based on OAuth

**CAUTION**: the developments are not finished, DO NOT USE

# Requirements
- PHP >=7.1.3
- symfony/http-client >= 4.3

# Installation

`composer require eureka2/oauth-client`

# Usage

## Low-level requests to a builtin OAuth provider
 ```php
use eureka2\OAuth\Client\OAuthClientFactory;

try {
    $client = OAuthClientFactory::create('Google');
    $client->setClientId('<YOUR CLIENT ID>');
    $client->setClientSecret('<YOUR CLIENT SECRET>');
    $client->setRedirectUri('http://' . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME']);
    $user = (object) [];
    if ($client->initialize([
        'strategy' => [
            'offline_access' => true
        ]
    ])) {
        if ($client->authenticate()) {
            if (!empty($client->getAccessToken())) {
                $user = $client->getResourceOwner();
            }
        }
        $client->finalize();
    }
    if ($client->shouldExit()) {
        exit;
    }
    ....
    // Do something with $user
} catch (\Exception $e) {
    // Do something with $e
}
```

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
      'name' => 'string',     // 'oauth' or 'openid' (default: 'oauth')
      'version' => 'string'   // '1.0', '1.0a', '2.0' for 'oauth' or '1.0' for 'openid' (default: '2.0')
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
      'user_id_field' => 'string', // default: 'sub'
      'address_field' => 'string',
      'birthdate_field' => 'string',
      'email_field' => 'string',
      'family_name_field' => 'string',
      'gender_field' => 'string',
      'given_name_field' => 'string',
      'locale_field' => 'string',
      'middle_name_field' => 'string',
      'name_field' => 'string',
      'nickname_field' => 'string',
      'phone_number_field' => 'string',
      'picture_field' => 'string'
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
    'authorization_in_header' => 'boolean',
    'parameters_in_url' => 'boolean',
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
|Name                                            | Description                                                                                          | Values | Default   |
|------------------------------------------------|------------------------------------------------------------------------------------------------------|--------|-----------|
|provider.protocol.name                          | The OAuth-based protocol supported by the OAuth provider                                             |        |           |
|provider.protocol.version                       | Version of the protocol supported by the OAuth provider                                              |        |           |
|provider.endpoints.discovery_endpoint           | URL that returns a JSON list of the OpenID/OAuth endpoints, supported scopes and claims, public keys |        |           |
|provider.endpoints.authorization_endpoint       | URL of the OAuth provider to redirect the browser so the user can grant access to the application.   |        |           |
|provider.endpoints.token_endpoint               | URL of the OAuth provider used to obtain an ID token, access token, and refresh token                |        |           |
|provider.endpoints.registration_endpoint        |  |
|provider.endpoints.introspection_endpoint       |  |
|provider.endpoints.revocation_endpoint          |  |
|provider.endpoints.request_token_endpoint       |  |
|provider.endpoints.userinfo_endpoint            |  |
|provider.endpoints.end_session_endpoint         |  |
|provider.endpoints.pin_dialog_url               |  |
|provider.endpoints.jwks_uri                     |  |
|provider.mapping.user_id_field                  |  |
|provider.mapping.address_field                  |  |
|provider.mapping.birthdate_field                |  |
|provider.mapping.email_field                    |  |
|provider.mapping.family_name_field              |  |
|provider.mapping.gender_field                   |  |
|provider.mapping.given_name_field               |  |
|provider.mapping.locale_field                   |  |
|provider.mapping.middle_name_field              |  |
|provider.mapping.name_field                     |  |
|provider.mapping.nickname_field                 |  |
|provider.mapping.phone_number_field             |  |
|provider.mapping.picture_field                  |  |
|provider.registration.keys.client_id            |  |
|provider.registration.keys.client_secret        |  |
|provider.registration.keys.redirect_uri         |  |
|provider.registration.keys.realm                |  |
|provider.registration.keys.api_key              |  |
|provider.registration.keys.pin                  |  |
|provider.registrationcredentials.oauth_username |  |
|provider.registrationcredentials.oauth_password |  |
|strategy.reauthentication_parameter             |  |
|strategy.offline_access                         |  |
|strategy.offline_access_parameter               |  |
|strategy.append_state_to_redirect_uri           |  |
|strategy.authorization_in_header                |  |
|strategy.parameters_in_url                      |  |
|strategy.token_request_method                   |  |
|strategy.signature_method                       |  |
|strategy.signature_certificate_file             |  |
|strategy.access_token_authentication            |  |
|strategy.access_token_parameter                 |  |
|strategy.default_access_token_type              |  |
|strategy.store_access_token_response            |  |
|strategy.refresh_token_authentication           |  |
|strategy.grant_type                             |  |
|strategy.get_token_with_api_key                 |  |
|strategy.access_token_content_type              |  |
|strategy.access_token_language                  |  |
|strategy.scope                                  |  |
|storage.type                                    |  |
|storage.key                                     |  |
|storage.dsn                                     |  |

# Methods

|Name              |Description |
|------------------|------------|
|[initialize](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_initialize)| Initialize the class variables and internal state. It must be called before calling other class functions. |
|[authenticate](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_authenticate)| Process the OAuth protocol interaction with the OAuth provider. |
|[callAPI](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_callAPI)| Send a HTTP request to the Web services API using a previously obtained access token via OAuth. |
|[getResourceOwner](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getResourceOwner)| Returns the information about the resource owner using a previously obtained access token via OAuth. |
|[fetchResourceOwner](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_fetchResourceOwner)| Performs the entire authentication process (initialization, authentication, ...) and returns information about the resource owner.|
|[finalize](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_finalize)| Clean up resources that may be used when processing the OAuth protocol or executing API calls. |
|[checkAccessToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_checkAccessToken)| Check if the access token has been retrieved and is valid. |
|[introspectToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_introspectToken)| Determines the active state of a token and the meta-information about this token. |
|[resetAccessToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_resetAccessToken)| Reset the access token to a state back when the user has not yet authorized the access to the OAuth server API. |
|[canRevokeToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_canRevokeToken)| Determines whether the revokeToken function can be called. |
|[revokeToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_revokeToken)| Revoke a previously obtained token so it becomes invalid. |
|[canLogOut](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_canLogOut)| Determines whether the logOut function can be called. |
|[logOut](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_logOut)| Calls the end-session endpoint to notify the provider that the end-user has logged out of the relying party site. |
|[shouldExit](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_shouldExit)| Determine if the current script should be exited. |
|[getAccessToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getAccessToken)| Returns the obtained access token upon successful OAuth authentication. |
|[getRefreshToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getRefreshToken| Returns the obtained refresh token upon successful OAuth authentication. |
|[getIdToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getIdToken)| Returns the obtained ID token upon successful OpenID authentication. |
|[getProvider](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getProvider)| Returns the current instance of the OAuthProvider class. |

### API documentation

[Documentation](http://eureka2.github.io/oauth-client/)

# Copyright and license

&copy; 2019 Eureka2 - Jacques Archimède. Code released under the [MIT license](https://github.com/eureka2/oauth-client/blob/master/LICENSE).

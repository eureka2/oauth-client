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
|Name                                            |Type  |Values                                        |Default           |Description                                                                      |
|------------------------------------------------|------|----------------------------------------------|------------------|---------------------------------------------------------------------------------|
|provider.protocol.name                          |string|openid, oauth                                 |oauth             |The OAuth-based protocol supported by the OAuth provider                                             |
|provider.protocol.version                       |string|1.0, 1.0a, 2.0                                |2.0               |Version of the protocol supported by the OAuth provider                                              |
|provider.endpoints.discovery_endpoint           |string|                                              |                  |URL that returns a JSON list of the OpenID/OAuth endpoints, supported scopes and claims, public keys |
|provider.endpoints.authorization_endpoint       |string|                                              |                  |URL of the OAuth provider to redirect the browser so the user can grant access to the application.   |
|provider.endpoints.token_endpoint               |string|                                              |                  |URL of the OAuth provider used to obtain an ID token, access token, and refresh token                |
|provider.endpoints.registration_endpoint        |string|                                              |                  |URL of an  administrator managed service that is used to dynamically register, update, delete, and retrieve information about an OAuth client |
|provider.endpoints.introspection_endpoint       |string|                                              |                  |URL of the OAuth provider used to inspect the underlying authorisation properties of a token.|
|provider.endpoints.revocation_endpoint          |string|                                              |                  |URL of the OAuth provider that enables clients to notify that an issued token is no longer needed and must be revoked |
|provider.endpoints.request_token_endpoint       |string|                                              |                  |URL of the OAuth provider to request the initial token for OAuth 1.0 and 1.0a servers. |
|provider.endpoints.userinfo_endpoint            |string|                                              |                  ||
|provider.endpoints.end_session_endpoint         |string|                                              |                  ||
|provider.endpoints.pin_dialog_url               |string|                                              |                  ||
|provider.endpoints.jwks_uri                     |string|                                              |                  ||
|provider.mapping.user_id_field                  |string|                                              |sub               ||
|provider.mapping.address_field                  |string|                                              |                  ||
|provider.mapping.birthdate_field                |string|                                              |                  ||
|provider.mapping.email_field                    |string|                                              |                  ||
|provider.mapping.family_name_field              |string|                                              |                  ||
|provider.mapping.gender_field                   |string|                                              |                  ||
|provider.mapping.given_name_field               |string|                                              |                  ||
|provider.mapping.locale_field                   |string|                                              |                  ||
|provider.mapping.middle_name_field              |string|                                              |                  ||
|provider.mapping.name_field                     |string|                                              |                  ||
|provider.mapping.nickname_field                 |string|                                              |                  ||
|provider.mapping.phone_number_field             |string|                                              |                  ||
|provider.mapping.picture_field                  |string|                                              |                  ||
|provider.registration.keys.client_id            |string|                                              |                  ||
|provider.registration.keys.client_secret        |string|                                              |                  ||
|provider.registration.keys.redirect_uri         |string|                                              |                  ||
|provider.registration.keys.realm                |string|                                              |                  ||
|provider.registration.keys.api_key              |string|                                              |                  ||
|provider.registration.keys.pin                  |string|                                              |                  ||
|provider.registration.credentials.oauth_username|string|                                              |                  ||
|provider.registration.credentials.oauth_password|string|                                              |                  ||
|strategy.reauthentication_parameter             |string|                                              |                  |The parameters to add to the OAuth provider authorization endpoint URL in case of new authentication.|
|strategy.offline_access                         |bool  |true, false                                   |false             |Specify whether it will be necessary to call the API when the user is not present and the provider supports renewing expired access tokens using refresh tokens.|
|strategy.offline_access_parameter               |string|                                              |                  |The parameter to add to the OAuth provider authorization endpoint URL when offline access is requested|
|strategy.append_state_to_redirect_uri           |string|                                              |state             |The name of the OAuth session state variable, if different from the standard name|
|strategy.authorization_in_header                |bool  |true, false                                   |true              |Determines if the OAuth parameters should be passed via HTTP Authorization request header.|
|strategy.parameters_in_url                      |bool  |true, false                                   |false             |Determines if the API call parameters should be moved to the calling URL.|
|strategy.token_request_method                   |string|GET, POST                                     |GET               |The HTTP method that should be used to request tokens from the provider|
|strategy.signature_method                       |string|PLAINTEXT, HMAC-SHA1, RSA-SHA1                |HMAC-SHA1         |The method to generate the signature for API request parameters values (Oauth 1.0 or 1.0a)|
|strategy.signature_certificate_file             |string|                                              |                  |The full path of the file containing a PEM encoded certificate/private key if signature_method is 'RSA-SHA1'|
|strategy.access_token_authentication            |string|basic, none                                   |                  |Determines if the requests to obtain a new access token should use authentication to pass the application client ID and secret.|
|strategy.access_token_parameter                 |string|                                              |oauth_token, access_token|The name of the access token parameter to be passed in API call requests.|
|strategy.default_access_token_type              |string|                                              |                  |The type of access token to be assumed when the OAuth provider does not specify an access token type.|
|strategy.store_access_token_response            |bool  |true, false                                   |false             |Option to determine if the original response for the access token request should be stored |
|strategy.refresh_token_authentication           |string|no                                            |                  |Option to determine if the requests to refresh an expired access token should use authentication to pass the application client ID and secret. |
|strategy.grant_type                             |string|client_credentials, password, authorization_code|authorization_code|The type of grant to obtain the OAuth 2 access token. |
|strategy.get_token_with_api_key                 |bool  |true, false                                   |false             |Option to determine if the access token should be retrieved using the API key value instead of the client secret. |
|strategy.access_token_content_type              |string|                                              |                  |Content type to be assumed when retrieving the response to a request to retrieve the access token. |
|strategy.access_token_language                  |string|                                              |                  |Language to be assumed when retrieving the response to a request to retrieve the access token. |
|strategy.scope                                  |string|                                              |                  |Permissions that your application needs to call the OAuth provider APIs |
|storage.type                                    |string|session, cookie, apcu, pdo                    |session           |The session storage mode (session: in $_SESSion, cookie: in browser cookies, apcu: in APC user store, pdo: in a PDO database)|
|storage.key                                     |string|                                              |                  |A key used to encrypt the cookies when the storage mode is 'cookie'|
|storage.dsn                                     |string|                                              |                  |The Data Source Name, or DSN, contains the information required to connect to the database if the storage mode is 'pdo'|

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
|[getRefreshToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getRefreshToken)| Returns the obtained refresh token upon successful OAuth authentication. |
|[getIdToken](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getIdToken)| Returns the obtained ID token upon successful OpenID authentication. |
|[getProvider](http://eureka2.github.io/oauth-client/eureka2/OAuth/Client/OAuthClientInterface.html#method_getProvider)| Returns the current instance of the OAuthProvider class. |

### API documentation

[Documentation of oauth-client classes](http://eureka2.github.io/oauth-client/)

# Copyright and license

&copy; 2019 Eureka2 - Jacques Archimède. Code released under the [MIT license](https://github.com/eureka2/oauth-client/blob/master/LICENSE).

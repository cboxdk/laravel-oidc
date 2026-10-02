---
title: Reference
description: Every key of config/oidc.php, its default and the rule it is checked against
weight: 21
---

# Configuration reference

The package reads `config('oidc')` into `Cbox\Oidc\Config\OidcConfig` the first
time it needs it, and checks every connection then. A refused value throws
`Cbox\Oidc\Exceptions\InvalidConfiguration` with the code
`oidc_config_invalid`, the full key (`$exception->key()`) and a fix
(`$exception->fix()`).

Numbers may be given as strings, as `env()` returns them.

## Top level

| Key | Default | Rule |
|---|---|---|
| `default` | `OIDC_CONNECTION`, else `main` | Must name a configured connection. Without it, the first connection. |
| `connections` | one connection, `main` | At least one. Names are letters, digits, `.`, `-` and `_`, at most 64 characters. |
| `http` | see below | |
| `cache` | see below | |
| `flow` | see below | |

`OidcConfig::connection($name)` returns a connection; `null` gives the default.
An unknown name throws `UnknownConnection` (`oidc_connection_unknown`), which
lists the configured names.

## Connection

| Key | Default | Rule |
|---|---|---|
| `issuer` | required | https, absolute, no user info, query or fragment. Compared exactly with the provider's metadata, so write it as the provider does, trailing slash or not. May contain `{tenantid}` once (Microsoft Entra multi-tenant). |
| `discovery_url` | `issuer` + `/.well-known/openid-configuration` | https. Required when the issuer contains `{tenantid}`. |
| `client_id` | required | Non-empty. |
| `client_secret` | `null` | Required for `client_secret_basic` and `client_secret_post`; dropped for the others. Redacted when the connection is dumped. |
| `client_auth` | `client_secret_basic` | `client_secret_basic`, `client_secret_post`, `private_key_jwt` (see `client_assertion`) or `none` (public client, PKCE only). |
| `client_assertion` | see below | Read only for `private_key_jwt`, and then required. |
| `redirect_uri` | required | Absolute http or https URL. Register exactly this URL at the provider. |
| `scopes` | `openid profile email` | Must contain `openid`. Each is an RFC 6749 scope token. Duplicates are dropped. |
| `algorithms` | `RS256 PS256 ES256 EdDSA` in the published file | Any of `RS256`, `RS384`, `RS512`, `PS256`, `PS384`, `PS512`, `ES256`, `ES384`, `ES512`, `EdDSA`. `none` and `HS*` are refused. |
| `leeway_seconds` | `60` | 0 to 300. Clock skew allowed for `exp`, `nbf`, `iat` and `auth_time`. |
| `max_token_age_seconds` | `600` | 1 to 86400. An ID token issued longer ago is refused. |
| `max_age` | `null` | 0 to 31536000. Sent as `max_age`; `auth_time` then becomes required. |
| `tenant` | `null` | `['claim' => ..., 'allowed' => [...]]`. The claim must be present and its value listed. `['*']` alone accepts any tenant. Required, on `tid`, when the issuer contains `{tenantid}`. |
| `groups` | `['source' => 'id_token', 'claim' => 'groups']` | `source` is `id_token`, `userinfo` or `none`. |
| `post_logout_redirect_uri` | `null` | Absolute http or https URL. |
| `authorization_parameters` | `[]` | Map of extra parameters, such as Google's `access_type`. `client_id`, `code_challenge`, `code_challenge_method`, `max_age`, `nonce`, `redirect_uri`, `request`, `request_uri`, `response_mode`, `response_type`, `scope` and `state` are refused, in any case. |

## client_assertion

Read when `client_auth` is `private_key_jwt`. The key is loaded when the
configuration is parsed, so a wrong key fails at once.

| Key | Default | Rule |
|---|---|---|
| `key` | `null` | The private key as PEM text. Exactly one of `key` and `key_path`. |
| `key_path` | `null` | A local PEM file this process can read. Stream wrappers (`https://`, `phar:`, `data:`) are refused. |
| `passphrase` | `null` | For an encrypted key. |
| `key_id` | `null` | Sent as the `kid` header. |
| `algorithm` | `RS256` | One of the ID token algorithms. The key must fit it: RSA of at least 2048 bits, EC on its curve, or Ed25519 for `EdDSA`. When the provider lists `token_endpoint_auth_signing_alg_values_supported`, it must be there. |
| `audience` | `token_endpoint` | `token_endpoint` (OpenID Connect Core; Entra and Okta require it) or `issuer` (not with a `{tenantid}` issuer). |
| `headers` | `[]` | Extra header members, such as Entra's `x5t#S256`. `alg`, `kid`, `typ`, `crit`, `jku`, `jwk`, `x5u`, `b64`, `enc` and `zip` are refused. |
| `lifetime_seconds` | `60` | 10 to 600. |

## flow

| Key | Default | Rule |
|---|---|---|
| `transaction_ttl_seconds` | `600` | 30 to 3600. How long a started login may wait for its callback. |
| `max_pending_transactions` | `5` | 1 to 50. Started logins kept per session, newest first. |

## http

| Key | Default | Rule |
|---|---|---|
| `timeout_seconds` | `5` | 0.1 to 60. |
| `connect_timeout_seconds` | `2` | 0.1 to 60. |
| `max_response_bytes` | `262144` | 1024 to 16777216. |

## cache

| Key | Default | Rule |
|---|---|---|
| `store` | `null` (the default store) | A cache store name. |
| `discovery_ttl_seconds` | `86400` | 0 to 604800. |
| `jwks_default_ttl_seconds` | `3600` | Within the min and max below. Used when the provider sends no `max-age`. |
| `jwks_min_ttl_seconds` | `300` | 0 to 604800, at most the max. |
| `jwks_max_ttl_seconds` | `86400` | 0 to 604800. |
| `jwks_refetch_cooldown_seconds` | `60` | 1 to 86400. An unknown `kid` refetches the keys at most once per window, across processes. |
| `stale_if_error_seconds` | `86400` | 0 to 604800. When a cached document is stale and the provider is unavailable (network error, timeout, 408, 429 or 5xx), the stale copy is used this much longer. A document the provider serves wrongly is never replaced by a stale copy. 0 fails at once. |

## Examples

The examples below are complete `config/oidc.php` files. The test suite loads
each one and parses it, so they stay valid.

### Google Workspace, one domain

Google needs `access_type=offline` and `prompt=consent` to issue a refresh
token, and puts the Workspace domain in the `hd` claim.

<!-- example: config -->
```php
<?php

return [
    'default' => 'google',
    'connections' => [
        'google' => [
            'issuer' => 'https://accounts.google.com',
            'client_id' => env('GOOGLE_CLIENT_ID', 'google-client-id'),
            'client_secret' => env('GOOGLE_CLIENT_SECRET', 'google-client-secret'),
            'redirect_uri' => 'https://app.example.com/oidc/google/callback',
            'algorithms' => ['RS256'],
            'tenant' => ['claim' => 'hd', 'allowed' => ['example.com']],
            'groups' => ['source' => 'none'],
            'authorization_parameters' => [
                'access_type' => 'offline',
                'prompt' => 'consent',
            ],
        ],
    ],
];
```

### Microsoft Entra ID, multi-tenant with an allow-list, next to a second provider

The `{tenantid}` issuer template is filled from the verified `tid` claim, and
only the listed tenants are accepted.

<!-- example: config -->
```php
<?php

return [
    'default' => 'entra',
    'connections' => [
        'entra' => [
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'discovery_url' => 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            'client_id' => env('ENTRA_CLIENT_ID', '00000000-0000-0000-0000-000000000001'),
            'client_secret' => env('ENTRA_CLIENT_SECRET', 'entra-client-secret'),
            'redirect_uri' => 'https://app.example.com/oidc/entra/callback',
            'algorithms' => ['RS256'],
            'tenant' => [
                'claim' => 'tid',
                'allowed' => [
                    '11111111-1111-1111-1111-111111111111',
                    '22222222-2222-2222-2222-222222222222',
                ],
            ],
        ],
        'keycloak' => [
            'issuer' => 'https://sso.example.com/realms/staff',
            'client_id' => 'cms',
            'client_auth' => 'none',
            'redirect_uri' => 'https://app.example.com/oidc/keycloak/callback',
            'scopes' => ['openid', 'profile', 'email', 'offline_access'],
            'algorithms' => ['ES256', 'EdDSA'],
        ],
    ],
];
```

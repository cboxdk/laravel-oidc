---
title: Refresh and userinfo
description: Renew a login's tokens with its refresh token, and read the person's claims from the userinfo endpoint
weight: 19
---

# Refresh and userinfo

A login gives you an access token that expires (often after an hour) and,
when you ask for it, a refresh token that renews it:

- `Oidc::refresh()` renews the tokens of a login (the service
  `Cbox\Oidc\Tokens\TokenRefresher` underneath);
- `Oidc::userInfo()` reads the person's claims from the provider's userinfo
  endpoint with an access token (`Cbox\Oidc\UserInfo\UserInfoEndpoint`).

## Getting a refresh token

Providers hand out refresh tokens only when asked:

- most (Entra, Okta, Keycloak, Auth0, Cbox ID): add `offline_access` to the
  connection's `scopes`;
- Google: set `authorization_parameters` to
  `['access_type' => 'offline', 'prompt' => 'consent']`.

The login's refresh token is `$result->tokens->refreshToken`. Keep it
server-side with the login's verified claims (`$result->claims`, a
`VerifiedClaims` that serializes as it is): the refresher needs both. A
refresh token is a password to the person's account at the provider. If you
keep it in the session, turn on `session.encrypt`, or encrypt it yourself with
`Crypt::encryptString()`.

## Refreshing

<!-- example: refresh -->
```php
<?php

use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Facades\Oidc;

// $claims and $refreshToken were kept from the login's CallbackResult.
try {
    $renewed = Oidc::refresh($claims, $refreshToken);
} catch (TokenRequestRejected $exception) {
    if ($exception->refreshTokenInvalid()) {
        // The provider ended the grant: revoked, expired or used up.
        return 'sign in again';
    }

    throw $exception;
}

// Keep these two from now on. A provider that rotates refresh tokens has
// retired the old one.
$claims = $renewed->claims;
$refreshToken = $renewed->refreshToken;

$info = Oidc::userInfo($claims, $renewed->tokens->accessToken);

return [$claims->subject, $renewed->rotated, $info->email()];
```

`Oidc::refresh($claims, $refreshToken, $scopes)` sends the refresh token to the
token endpoint of the connection `$claims` came from, with the connection's
client authentication, and returns a `RefreshResult`:

| Property | What it holds |
|---|---|
| `tokens` | The new `TokenSet`: `accessToken`, `expiresAt` and the rest. |
| `refreshToken` | The refresh token to keep: the new one when the provider rotated it, else the one you passed. |
| `rotated` | Whether the provider returned a new refresh token. |
| `claims` | The verified claims of the new ID token; the original claims when the provider returned none. |
| `idTokenRenewed` | Whether the provider returned a new ID token. |

`$scopes` (a list) narrows the new access token; leave it null to keep the
original grant.

### The refreshed ID token

An ID token that comes back from a refresh passes every
[ID token rule](id-token-verification.md) except the nonce and `max_age`, and
must belong to the login it renews (OpenID Connect Core 12.2). Otherwise it
fails with `oidc_refreshed_id_token_mismatch`:

- `iss` and `sub` are the original ones;
- the tenant (`tid`, `hd`), when the connection pins one, is the original one;
- `auth_time`, when present, is still the time of the original sign-in;
- `nonce`, when present, is the original one.

When the connection reads groups from userinfo, the refreshed claims keep the
groups of the original claims until you call userinfo again.

### When a refresh fails

| Exception | Code | What to do |
|---|---|---|
| `TokenRequestRejected`, with `refreshTokenInvalid()` true | `oidc_token_request_rejected` (`invalid_grant`) | The grant is over. Drop the refresh token and sign the person in again. |
| `TokenRequestRejected` with another error | `oidc_token_request_rejected` | `invalid_client` and the like: the client configuration needs a look. |
| `ProviderUnavailable` | `oidc_provider_unavailable` | The provider is down or slow. Retry later; the session is not over. |
| `TokenRejected` | the rule's code | The new ID token failed verification. Treat the session as over. |
| `InvalidArgument` | `oidc_argument_invalid` | The stored refresh token or a scope is malformed. |

## Userinfo

`Oidc::userInfo($claims, $accessToken)` (`UserInfoEndpoint::fetch()`) calls
the provider's `userinfo_endpoint` with the access token as a Bearer token
and returns a `UserInfo`: `subject`, `groups` and the claims, read with the
typed readers (`string()`, `int()`, `bool()`, `stringList()`, `time()`),
`email()`, `emailVerified()`, `name()`, and untyped with `claim()`, `has()`
and `all()`, as on `VerifiedClaims`.

- The response's `sub` must be the ID token's subject, or it fails with
  `oidc_userinfo_subject_mismatch` (OpenID Connect Core 5.3.4): the claims
  could belong to someone else.
- 401 and 403 fail with `UserInfoRejected` (`oidc_userinfo_rejected`), whose
  `error()` is the Bearer error, such as `invalid_token` (refresh the access
  token) or `insufficient_scope`.
- Only plain JSON is read. A signed or encrypted response
  (`application/jwt`) is refused; configure the client at the provider to
  return JSON.
- `supported($connection)` tells whether the provider has the endpoint; a
  call without one fails with `oidc_endpoint_not_supported`.

Userinfo claims are not signed; they are as trustworthy as the TLS connection
to the provider. Identify the person by the ID token's issuer and subject.

### Groups from userinfo

Some providers put groups only in userinfo. Set the connection's
`groups.source` to `userinfo` (and `groups.claim` to the claim's name), and
the login callback calls userinfo for you: `$result->claims->groups` then
holds the userinfo groups, and `$result->userInfo` the whole response. A
login whose userinfo fails, fails.

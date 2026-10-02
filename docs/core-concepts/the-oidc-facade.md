---
title: The Oidc facade
description: Every call of the Oidc facade and the OidcClient contract, and how to use several connections
weight: 16
---

# The Oidc facade

`Cbox\Oidc\Facades\Oidc` (alias `Oidc`) is the front of the package. It
calls the `Cbox\Oidc\Contracts\OidcClient` bound in the container, so a
controller can type-hint the contract instead. `Oidc::fake()` swaps both for
the [testing fake](../getting-started/testing.md).

| Call | Returns | See |
|---|---|---|
| `Oidc::redirect($connection, $options)` | the redirect to the provider | [the login flow](login-flow.md) |
| `Oidc::start($connection, $options)` | an `AuthorizationRequest`: the URL, the state | [the login flow](login-flow.md) |
| `Oidc::callback($connection, $request)` | a `CallbackResult` with the verified claims and tokens | [the login flow](login-flow.md) |
| `Oidc::refresh($claims, $refreshToken, $scopes)` | a `RefreshResult` | [refresh and userinfo](refresh-and-userinfo.md) |
| `Oidc::userInfo($claims, $accessToken)` | a `UserInfo` | [refresh and userinfo](refresh-and-userinfo.md) |
| `Oidc::logout($connection, $options, $fallback)` | the redirect to the provider's logout, or to `$fallback` | [logout](logout.md) |
| `Oidc::revoke($token, $hint, $connection)` | nothing | [logout](logout.md#revocation) |
| `Oidc::connection($name)` | the same calls bound to one connection | below |

A null connection is the default one, `oidc.default`. `refresh()` and
`userInfo()` take no connection: the claims name the one they came from.
`callback()` reads the current request when none is passed. Every failure is
an `OidcException` with a [code and a fix](errors.md).

## Several connections

Give each connection its own login and callback routes, and register each
callback URL at its provider. `connection()` binds the calls to one:

<!-- example: facade-controller -->
```php
<?php

namespace App\Http\Controllers;

use Cbox\Oidc\Contracts\OidcClient;
use Illuminate\Http\RedirectResponse;

final class OidcLoginController
{
    public function __construct(private OidcClient $oidc) {}

    public function redirect(string $connection): RedirectResponse
    {
        return $this->oidc->connection($connection)->redirect();
    }

    public function callback(string $connection): RedirectResponse
    {
        $claims = $this->oidc->connection($connection)->callback()->claims;

        // Find or create the user by $claims->issuer and $claims->subject.
        return redirect('/')->with('status', "Signed in through {$connection}.");
    }
}
```

`connection()` fails with `oidc_connection_unknown` for a name that is not
configured, so a route parameter cannot reach a connection you did not set up;
constrain the parameter with `whereIn()` as well to answer such a request with
404.

## The services underneath

The facade is a thin front over services you can resolve for the less common
calls: `AuthorizationFlow`, `TokenRefresher`, `UserInfoEndpoint`,
`LogoutFlow` and `TokenRevocation`, plus `IdTokenVerifier`,
`LogoutTokenVerifier`, `MetadataRepository` and `KeySetRepository`. Code that
uses them directly is not replaced by `Oidc::fake()`.

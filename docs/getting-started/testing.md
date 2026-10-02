---
title: Testing
description: Test your login, refresh, logout and back-channel logout code with Oidc::fake()
weight: 12
---

# Testing

`Oidc::fake()` replaces the client behind the `Oidc` facade and the
`Cbox\Oidc\Contracts\OidcClient` contract with `Cbox\Oidc\Testing\OidcFake`.
Nothing reaches a provider: no discovery, no keys, no HTTP. You queue what the
provider answers, run your routes, and assert what your code asked for.

The examples on this page test the routes of [the login flow](../core-concepts/login-flow.md#routes)
and [logout](../core-concepts/logout.md#logging-out), and the test suite runs
them against those routes.

## Signing in

Each callback takes the next outcome queued for its connection. `signIn()`
queues a successful one; its claims replace the defaults (`iss`, `sub`, `aud`,
`iat`, `exp`, `auth_time`, `nonce`, `sid`):

<!-- example: testing-sign-in -->
```php
<?php

use Cbox\Oidc\Facades\Oidc;

it('signs a person in', function () {
    $oidc = Oidc::fake()->signIn('user-1', ['groups' => ['staff']]);

    $this->get('/oidc/main/login')->assertRedirect();
    $this->get('/oidc/main/callback')->assertOk()->assertJson(['subject' => 'user-1', 'groups' => ['staff']]);

    $oidc->assertRedirected('main');
    $oidc->assertSignedIn('user-1');
    $oidc->assertNoPendingSignIns();
});
```

The fake does not check the callback's state or code, so a test can call the
callback route directly. A callback with nothing queued throws a
`LogicException` that says so. The issuer is the connection's configured
issuer (with `tid` filled into an Entra `{tenantid}` template), groups come
from the connection's groups claim, and the tenant from its tenant claim.

## Failed sign-ins

`denySignIn($error)` queues an OAuth error from the provider, and
`failSignIn($exception)` any `OidcException`:

<!-- example: testing-failures -->
```php
<?php

use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Facades\Oidc;

it('tells a person of another organisation that it cannot sign in', function () {
    Oidc::fake()->failSignIn(TenantRejected::notAllowed('main', 'hd', 'example.org'));

    $this->get('/oidc/main/callback')
        ->assertRedirect('/')
        ->assertSessionHas('status', 'Your organisation cannot sign in here.');
});

it('answers a cancelled sign-in', function () {
    Oidc::fake()->denySignIn('access_denied');

    $this->get('/oidc/main/callback')->assertSessionHas('status', 'Sign-in was cancelled.');
});

it('starts an interactive sign-in when a silent one needs the person', function () {
    $oidc = Oidc::fake()->denySignIn('login_required');

    $this->get('/oidc/main/callback')->assertRedirect();

    $oidc->assertRedirected('main');
});
```

## Refresh and userinfo

Refresh tokens rotate: a refresh returns a new one, and the old one, like a
revoked one, then fails with `invalid_grant`, as at a provider that rotates.
`failRefresh($exception)` makes the next refresh fail, and `withUserInfo()`
adds userinfo claims.

<!-- example: testing-refresh -->
```php
<?php

use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Facades\Oidc;

it('keeps the rotated refresh token', function () {
    $oidc = Oidc::fake()->signIn('user-1');
    $login = Oidc::callback();

    $renewed = Oidc::refresh($login->claims, $login->tokens->refreshToken);

    expect($renewed->refreshToken)->not->toBe($login->tokens->refreshToken)
        ->and(fn () => Oidc::refresh($login->claims, $login->tokens->refreshToken))
        ->toThrow(TokenRequestRejected::class, 'invalid_grant');

    $oidc->assertRefreshed();
});
```

## Logout

`logout()` sends the browser straight to where the provider would send it
back: the `postLogoutRedirectUri` option, else the connection's
`post_logout_redirect_uri`, else the fallback.

<!-- example: testing-logout -->
```php
<?php

use Cbox\Oidc\Facades\Oidc;

it('revokes the refresh token and logs out at the provider', function () {
    $oidc = Oidc::fake();

    $this->withSession(['oidc.refresh_token' => 'refresh-1'])->post('/logout')->assertRedirect('/');

    $oidc->assertRevoked('refresh-1');
    $oidc->assertLoggedOut();
});
```

## Back-channel logout

`backChannelLogout($subject, $sessionId)` dispatches
`BackChannelLogoutReceived` as the receiver route does for a verified logout
token, so your listener runs. This one tests the listener of
[back-channel logout](../core-concepts/logout.md#back-channel-logout):

<!-- example: testing-backchannel -->
```php
<?php

use Cbox\Oidc\Facades\Oidc;

it('signs out a session the provider ended', function () {
    $oidc = Oidc::fake()->signIn('user-1');
    $claims = Oidc::callback()->claims;

    $oidc->backChannelLogout(sessionId: $claims->sessionId);

    $this->withSession(['oidc.claims' => $claims])->get('/account')->assertRedirect('/login');
});
```

## Assertions

In each, a null connection means any connection.

| Assertion | Passes when |
|---|---|
| `assertRedirected($connection, $callback)` | A login was started; `$callback` gets its `AuthorizationOptions` and `AuthorizationRequest`. |
| `assertNotRedirected($connection)` | No login was started. |
| `assertSignedIn($subject, $connection)` | A callback succeeded, for `$subject` when given. |
| `assertNotSignedIn($connection)` | No callback succeeded. |
| `assertNoPendingSignIns()` | Every queued outcome was used by a callback. |
| `assertRefreshed($connection)`, `assertNotRefreshed($connection)` | A refresh did or did not happen. |
| `assertLoggedOut($connection, $callback)`, `assertNotLoggedOut($connection)` | A logout did or did not happen; `$callback` gets its `LogoutOptions`. |
| `assertRevoked($token, $connection)`, `assertNotRevoked($connection)` | A token (that token, when given) was or was not revoked. |

`signIns($connection)` returns the `CallbackResult` of each successful
callback.

## What the fake is not

- Its tokens are not signed. The ID token is an unsecured JWT (`alg: none`)
  that the package's verifier refuses, so it can never pass for a real one.
- It reads connection names and a few values (issuer, client id, redirect
  URI, scopes, groups, tenant claim and `post_logout_redirect_uri`) from
  `config/oidc.php` without the checks of the real configuration. With no
  connections configured, any name is accepted.
- It replaces the facade and the contract. Code that resolves the services
  (`AuthorizationFlow`, `TokenRefresher` and the others) directly still calls
  the provider; fake its HTTP with `Http::fake()` and give its host a public
  address with laravel-ssrf's `InteractsWithSsrf::fakeSsrfDns()`.

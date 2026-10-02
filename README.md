# Cbox OIDC

Sign people in to a Laravel application through any OpenID provider:
Microsoft Entra ID, Google Workspace, Okta, Keycloak, Auth0, Cbox ID and
others. The authorization code flow with PKCE, full ID token verification,
issuer and tenant pinning, refresh, logout and back-channel logout, with
every call to the provider behind an SSRF guard.

<!-- example: setup-routes -->
```php
<?php

use App\Models\User;
use Cbox\Oidc\Facades\Oidc;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::get('/login', fn () => Oidc::redirect())->name('login');

Route::get('/oidc/callback', function () {
    $claims = Oidc::callback()->claims;

    Auth::login(User::updateOrCreate(
        ['oidc_issuer' => $claims->issuer, 'oidc_subject' => $claims->subject],
        ['name' => $claims->name() ?? $claims->subject, 'email' => $claims->email()],
    ));
    session()->regenerate();

    return redirect()->intended('/');
});
```

`$claims` are verified: signature, issuer, audience, nonce, times and tenant.
Identify the person by `$claims->issuer` and `$claims->subject` together.

> **Status: in development, not released.** Version 0.1 is complete in scope
> and being reviewed before its first release. The [changelog](CHANGELOG.md)
> lists what it holds.

## Why

Getting OpenID Connect right takes more than decoding a JWT. The ID token must
be checked against a pinned issuer, the right audience, a nonce bound to the
browser's session, an algorithm allow-list, and keys that rotate. The calls to
the provider are outbound HTTP to URLs that come from a document the provider
serves, which is an SSRF surface. This package does those checks in one place,
with the cryptography left to an established library,
[`web-token/jwt-library`](https://github.com/web-token/jwt-library), and every
outbound call guarded by
[`cboxdk/laravel-ssrf`](https://github.com/cboxdk/laravel-ssrf).

## What it does

- Several named connections in `config/oidc.php`, checked into typed objects:
  a wrong value fails at once with the key and the fix.
- Discovery with an exact issuer match (RFC 8414), and the provider's keys
  cached with their lifetime and refetched once, rate-limited, on an unknown
  `kid`.
- The authorization code flow with PKCE S256, state and nonce kept in the
  session, and the RFC 9207 `iss` check.
- ID token verification: signature through the provider's keys, a
  per-connection algorithm allow-list, `iss`, `aud`, `azp`, `exp`, `nbf`,
  `iat` with leeway, `nonce`, `at_hash`, `auth_time` and `max_age`.
- Tenant pinning: Microsoft Entra multi-tenant (`{tenantid}` checked against
  `tid`, with an allow-list) and the Google Workspace `hd` claim.
- Refresh tokens, userinfo with the `sub` match, RP-initiated logout, token
  revocation, and a back-channel logout receiver with `jti` replay protection
  that dispatches a Laravel event.
- `Oidc::fake()` for your tests, and `php artisan oidc:check` to see whether
  a connection works and why not.
- Exceptions with a stable code and a one-line fix.

## Install

```bash
composer require cboxdk/laravel-oidc
php artisan vendor:publish --tag=oidc-config
```

Then set the connection in your environment and check it:

```dotenv
OIDC_ISSUER=https://login.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
```

```bash
php artisan oidc:check
```

The [quickstart](docs/quickstart.md) walks through the users table and the
routes above; the [provider pages](docs/providers/_index.md) have a tested
configuration for each common provider.

## Testing your application

<!-- example: setup-test -->
```php
<?php

use App\Models\User;
use Cbox\Oidc\Facades\Oidc;

it('signs a person in through the provider', function () {
    Oidc::fake()->signIn('user-1', ['email' => 'ada@example.com', 'name' => 'Ada Lovelace']);

    $this->get('/login')->assertRedirect();
    $this->get('/oidc/callback')->assertRedirect('/');

    $this->assertAuthenticatedAs(User::where('oidc_subject', 'user-1')->sole());
});
```

`Oidc::fake()` queues what the provider answers (`signIn()`, `denySignIn()`,
`failSignIn()`), records what your code asked for, and asserts it. See
[testing](docs/getting-started/testing.md).

## Errors

Every exception extends `OidcException` and carries a stable code and a fix:

<!-- example: error-message -->
```text
[oidc_discovery_issuer_mismatch] The discovery document of connection "main" names the issuer "https://login.example.com/", but the connection pins "https://login.example.com". They must be equal, character for character (RFC 8414 3.3). Fix: If "https://login.example.com/" is the provider you mean, set oidc.connections.main.issuer to it exactly, trailing slash included. Otherwise check discovery_url.
```

See [errors](docs/core-concepts/errors.md) for the list.

## Honest scope

- The package is a relying party only. It is not an OpenID provider and issues
  no tokens to others.
- Encrypted ID tokens (JWE), signed userinfo responses, pushed authorization
  requests (PAR), DPoP and the form_post response mode are not part of 0.1.
- Front-channel logout is not supported. Back-channel logout verifies the
  token and dispatches an event; ending the sessions it names is up to your
  application.
- The SSRF guard is defence in depth: a network egress allow-list is the only
  complete control.
- Provider calls are https only and never follow redirects, so a provider
  running on a private network or on `localhost` is refused unless you change
  `config/ssrf.php` on purpose.
- A key set can stay cached for up to `jwks_max_ttl_seconds` (plus
  `stale_if_error_seconds` during an outage). When a provider withdraws a
  compromised key, drop the cache yourself; every process that shares the
  cache store stops using the old key within five seconds. See
  [discovery and keys](docs/core-concepts/discovery-and-keys.md#caching).

## Testing the package

```bash
composer qa
```

runs Pint, Rector, PHPStan at level max, the Pest suites, the license check and
`composer audit`. Every code sample in the documentation and this README is run
by the test suite.

## Documentation

- [Overview](docs/index.md)
- [Quickstart](docs/quickstart.md)
- [Requirements](docs/requirements.md)
- [Installation](docs/getting-started/installation.md)
- [Testing](docs/getting-started/testing.md)
- [Checking a connection](docs/getting-started/checking-a-connection.md)
- [Configuration reference](docs/configuration/reference.md)
- [Providers](docs/providers/_index.md): [Google](docs/providers/google.md), [Microsoft Entra ID](docs/providers/microsoft-entra.md), [Okta](docs/providers/okta.md), [Keycloak](docs/providers/keycloak.md), [Auth0](docs/providers/auth0.md), [Cbox ID](docs/providers/cbox-id.md)
- [The Oidc facade](docs/core-concepts/the-oidc-facade.md)
- [Discovery and keys](docs/core-concepts/discovery-and-keys.md)
- [The login flow](docs/core-concepts/login-flow.md)
- [ID token verification](docs/core-concepts/id-token-verification.md)
- [Refresh and userinfo](docs/core-concepts/refresh-and-userinfo.md)
- [Logout](docs/core-concepts/logout.md)
- [Errors](docs/core-concepts/errors.md)
- [HTTP client and clock](docs/extension-points/http-client.md)
- [Transaction store](docs/extension-points/transaction-store.md)
- [Security](docs/security/_index.md)

## License

MIT. See [LICENSE](LICENSE).

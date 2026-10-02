# Cbox OIDC

An OpenID Connect relying party for Laravel. It signs people in through any
OpenID provider (Microsoft Entra ID, Google Workspace, Okta, Keycloak, Auth0,
Cbox ID) with the authorization code flow, PKCE and full ID token
verification, and hands your application a typed, verified result.

> **Status: in development, not released.** Version 0.1 is being built in
> slices. Today the package has its typed, multi-connection configuration,
> discovery and signing-key handling behind the SSRF guard, and the
> authorization code flow through full ID token verification with issuer and
> tenant pinning. Refresh, userinfo, logout, back-channel logout and the
> testing fake land in the next slices. The [changelog](CHANGELOG.md) lists
> what exists.

## Why

Getting OpenID Connect right takes more than decoding a JWT. The ID token must
be checked against a pinned issuer, the right audience, a nonce bound to the
browser's session, an algorithm allow-list, and keys that rotate. The calls to
the provider are outbound HTTP to URLs that come from a document the provider
serves, which is an SSRF surface. This package does those checks in one place,
with the cryptography left to an established library.

## Scope of 0.1

- Several named connections (providers or tenants) in `config/oidc.php`,
  checked into typed objects. Done.
- Discovery with an exact issuer match (RFC 8414) and cached metadata. Done.
- The provider's signing keys (JWKS): cached with the provider's lifetime,
  refetched once on an unknown `kid` with a cross-process cooldown, and each
  key checked for type, curve, size, use and alg before it may verify. Done.
- Authorization code flow with PKCE (S256), with state and nonce in the
  session, the RFC 9207 `iss` check, and the code exchange with
  `client_secret_basic`, `client_secret_post`, `private_key_jwt` or a public
  client. Done.
- ID token verification: signature through the provider's JWKS (refetched once,
  rate-limited, on an unknown `kid`), a per-connection algorithm allow-list,
  `iss`, `aud`, `azp`, `exp`, `nbf`, `iat` with leeway, `nonce`, `at_hash`,
  `auth_time` and `max_age`, and a typed `VerifiedClaims` result. Done.
- Issuer and tenant pinning: Microsoft Entra multi-tenant (`{tenantid}` checked
  against `tid`, with per-tenant allow-lists) and the Google Workspace `hd`
  claim. Done.
- Refresh tokens, userinfo (with the `sub` match), RP-initiated logout and token
  revocation.
- A back-channel logout receiver that verifies the logout token and dispatches a
  Laravel event, with `jti` replay protection.
- A testing fake for your application's tests.

Cryptography (JWK and JWKS parsing, signature verification, claim checks) comes
from [`web-token/jwt-library`](https://github.com/web-token/jwt-library). The
package never hand-writes it. Every outbound call goes through an injectable
client guarded by [`cboxdk/laravel-ssrf`](https://github.com/cboxdk/laravel-ssrf).

## Install

```bash
composer require cboxdk/laravel-oidc
php artisan vendor:publish --tag=oidc-config
```

Then set the connection in your environment:

```dotenv
OIDC_ISSUER=https://login.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
```

## Configuration

`config/oidc.php` holds one entry per connection under `connections`, and the
`default` connection name. Each value is checked the first time the package
needs it; a wrong value throws `InvalidConfiguration` with a stable code, the
full key and the fix:

```text
[oidc_config_invalid] oidc.connections.main.issuer must be an absolute https URL. Fix: Set oidc.connections.main.issuer to a full URL starting with https://.
```

See the [configuration reference](docs/configuration/reference.md) for every key.

## Usage

Give each connection a login route and its own callback route:

```php
use Cbox\Oidc\Flow\AuthorizationFlow;
use Illuminate\Http\Request;

Route::middleware('web')->group(function () {
    Route::get('/oidc/{connection}/login', fn (AuthorizationFlow $oidc, string $connection) => $oidc->start($connection));

    Route::get('/oidc/{connection}/callback', function (Request $request, AuthorizationFlow $oidc, string $connection) {
        $claims = $oidc->callback($request, $connection)->claims;

        // Verified: find or create your user by issuer and subject.
        $user = User::firstOrCreate(['oidc_issuer' => $claims->issuer, 'oidc_subject' => $claims->subject], ['email' => $claims->email()]);
        Auth::login($user);
        $request->session()->regenerate();

        return redirect('/');
    });
});
```

`start()` sends the browser to the provider with a fresh state, nonce and PKCE
challenge. `callback()` checks the state, the `iss` parameter and any error,
exchanges the code and verifies the ID token. `$result->claims` holds the
issuer, subject, `auth_time`, `amr`, `acr`, tenant, groups and every other
claim. See [the login flow](docs/core-concepts/login-flow.md) for options such
as `prompt`, `max_age` and `login_hint` and the full example with error
handling, and [ID token verification](docs/core-concepts/id-token-verification.md)
for every rule and the Google and Entra tenant policies.

## Errors

Every exception extends `OidcException` and carries a stable code and a fix.
See [errors](docs/core-concepts/errors.md) for the list.

## Honest scope

- The package is a relying party only. It is not an OpenID provider and issues
  no tokens to others.
- Encrypted ID tokens (JWE), signed userinfo responses, pushed authorization
  requests (PAR), DPoP and the form_post response mode are not part of 0.1.
- Front-channel logout is not supported.
- The SSRF guard is defence in depth: a network egress allow-list is the only
  complete control. See the guard's own documentation.
- Provider calls are https only and never follow redirects, so a provider
  running on a private network or on `localhost` is refused unless you change
  `config/ssrf.php` on purpose.
- A key set can stay cached for up to `jwks_max_ttl_seconds` (plus
  `stale_if_error_seconds` during an outage). When a provider withdraws a
  compromised key, drop the cache yourself; see
  [discovery and keys](docs/core-concepts/discovery-and-keys.md#caching).

## Testing

```bash
composer qa
```

runs Pint, Rector, PHPStan at level max, the Pest suites, the license check and
`composer audit`.

## Documentation

- [Overview](docs/index.md)
- [Quickstart](docs/quickstart.md)
- [Requirements](docs/requirements.md)
- [Installation](docs/getting-started/installation.md)
- [Configuration reference](docs/configuration/reference.md)
- [Discovery and keys](docs/core-concepts/discovery-and-keys.md)
- [Errors](docs/core-concepts/errors.md)
- [HTTP client and clock](docs/extension-points/http-client.md)
- [Security](docs/security/_index.md)

## License

MIT. See [LICENSE](LICENSE).

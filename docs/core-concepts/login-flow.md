---
title: The login flow
description: Start a login, handle the callback, and what each step checks
weight: 17
---

# The login flow

The package runs the authorization code flow with PKCE (OpenID Connect Core
3.1) through one service, `Cbox\Oidc\Flow\AuthorizationFlow`:

- `start($connection, $options)` makes a fresh state, nonce and PKCE verifier,
  keeps them server-side, and returns an `AuthorizationRequest`: the URL to
  send the browser to. Return it from a route and Laravel answers with the
  redirect. `redirect()` returns the `RedirectResponse` directly.
- `callback($request, $connection)` checks the browser's return and exchanges
  the code for tokens. It returns a `CallbackResult`.

> **In development.** In this version `callback()` stops after the code
> exchange: `CallbackResult::$tokens->idToken` is not verified yet. ID token
> verification, and the typed claims built from it, are the next slice of
> 0.1. Do not sign anyone in from an unverified token.

## Routes

Give each connection its own callback URL, register exactly that URL at the
provider, and pass the connection to `callback()`. A response meant for one
provider then never reaches another (the mix-up defence of RFC 9207 section
1). Both routes need the `web` middleware group, because the login waits in
the session.

<!-- example: login-routes -->
```php
<?php

use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Flow\AuthorizationRequest;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('web')->group(function (): void {
    $connections = array_keys((array) config('oidc.connections'));

    Route::get('/oidc/{connection}/login', fn (AuthorizationFlow $oidc, string $connection): AuthorizationRequest => $oidc->start($connection))
        ->whereIn('connection', $connections);

    Route::get('/oidc/{connection}/callback', function (Request $request, AuthorizationFlow $oidc, string $connection): RedirectResponse|JsonResponse|AuthorizationRequest {
        try {
            $result = $oidc->callback($request, $connection);
        } catch (AuthorizationDenied $denied) {
            // A silent login (prompt=none) that needs the person: ask them.
            return $denied->interactionRequired()
                ? $oidc->start($connection)
                : redirect('/')->with('status', 'Sign-in was cancelled.');
        } catch (OidcException $exception) {
            report($exception);

            return redirect('/')->with('status', 'Sign-in failed. Please try again.');
        }

        // Until ID token verification lands, only show what came back.
        return response()->json([
            'connection' => $result->connection,
            'expires_in' => $result->tokens->expiresIn,
            'has_refresh_token' => $result->tokens->refreshToken !== null,
        ]);
    })->whereIn('connection', $connections);
});
```

## Options per login

`AuthorizationOptions` adds to what the connection configures:

```php
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;

$oidc->start('entra', new AuthorizationOptions(
    prompt: Prompt::Login,          // or [Prompt::Login, Prompt::Consent]
    maxAge: 0,                      // re-authenticate now; auth_time becomes required
    loginHint: 'ada@example.com',
    scopes: ['offline_access'],     // added to the connection's scopes
    acrValues: ['urn:example:mfa'],
    parameters: ['domain_hint' => 'example.com'],
));
```

Every option is checked when it is written; a wrong one throws
`InvalidAuthorizationOptions` (`oidc_authorization_options_invalid`):
`Prompt::None` with another prompt, a protocol parameter in `parameters`, a
scope with a space, and so on. An option replaces the connection's
`authorization_parameters` of the same name, so `prompt: Prompt::SelectAccount`
wins over a configured `prompt => consent`.

## What start() sends

The URL carries `response_type=code`, `client_id`, `redirect_uri`, `scope`,
`state`, `nonce`, `code_challenge` and `code_challenge_method=S256`, then
`max_age`, `prompt`, `login_hint` and `acr_values` when set, then the extra
parameters. The state and nonce are 32 random bytes each, and the PKCE
verifier is 32 random bytes (43 characters). S256 is always used, also for
confidential clients. A query the provider's `authorization_endpoint` already
has is kept; one that sets a parameter of the request is refused. The URL
passes the SSRF guard's redirect check before the browser is sent there.

## What callback() checks, in order

1. **State.** The callback's `state` must match a login this session started
   for this connection. The login is used up whether the rest passes or not,
   and it must be younger than `oidc.flow.transaction_ttl_seconds` (600 by
   default). Failures: `oidc_state_mismatch`, `oidc_transaction_expired`.
2. **Issuer (RFC 9207).** When the callback carries `iss`, or the provider
   announces `authorization_response_iss_parameter_supported`, `iss` must be
   the pinned issuer. For an Entra `{tenantid}` issuer, `iss` must be the
   template with one tenant filled in. Failure: `oidc_callback_issuer_mismatch`.
3. **Error.** An `error` answer becomes `AuthorizationDenied`
   (`oidc_authorization_denied`) with the error code in `error()`.
   `error_description` is never read: anyone can put text in a callback URL.
4. **Code.** It must be present and 1 to 2048 printable ASCII characters.
   Failure: `oidc_callback_invalid`.
5. **Exchange.** The code goes to the token endpoint with the PKCE verifier,
   the redirect URI and the connection's client authentication. The response
   must be JSON with an `access_token`, `token_type` Bearer and an `id_token`.
   An OAuth error is `TokenRequestRejected` (`oidc_token_request_rejected`)
   with its code in `error()`.

The state is checked before anything else, so a forged error or code that
does not carry a live state is refused without a call to the provider.

## Client authentication

`client_auth` picks how the token request authenticates:

| Method | What is sent |
|---|---|
| `client_secret_basic` (default) | HTTP Basic with the client id and secret, each form-encoded first (RFC 6749 2.3.1). |
| `client_secret_post` | `client_id` and `client_secret` in the form. |
| `private_key_jwt` | `client_id`, `client_assertion_type` and a JWT signed with your private key (RFC 7523). |
| `none` | `client_id` only: a public client, bound by PKCE. |

For `private_key_jwt`, the key and its settings live under `client_assertion`:

```php
'client_auth' => 'private_key_jwt',
'client_assertion' => [
    'key_path' => storage_path('oidc/client.pem'),   // or 'key' => env('OIDC_CLIENT_KEY')
    'key_id' => env('OIDC_CLIENT_KEY_ID'),
    'algorithm' => 'RS256',
    'audience' => 'token_endpoint',
    // Microsoft Entra with a certificate: its SHA-256 thumbprint.
    'headers' => ['x5t#S256' => env('OIDC_CLIENT_CERT_THUMBPRINT')],
],
```

The key is read when the configuration is parsed. It must be a private RSA (at
least 2048 bits), EC or Ed25519 key that fits the algorithm; an encrypted key
needs `passphrase`. Each assertion has `iss` and `sub` set to the client id,
`aud` set to the token endpoint (or the issuer with `audience => issuer`), a
fresh `jti`, and `iat`, `nbf` and `exp` from the clock, valid for
`lifetime_seconds` (60 by default). When the provider lists
`token_endpoint_auth_signing_alg_values_supported`, the algorithm must be on
it.

## Sessions and cookies

The default `TransactionStore` keeps started logins in the Laravel session,
under the SHA-256 of their state, so several tabs can each have a login in
flight; at most `oidc.flow.max_pending_transactions` (5) are kept. The session
cookie must reach the callback: keep it `SameSite=lax`, not `strict`, or the
browser leaves it off the provider's redirect back and every login fails with
`oidc_state_mismatch`. Regenerate the session once you sign the person in. To
keep logins somewhere else, see [the transaction store](../extension-points/transaction-store.md).

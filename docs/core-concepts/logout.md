---
title: Logout
description: End the session at the provider, revoke its tokens, and receive back-channel logout from the provider
weight: 22
---

# Logout

Three things can end a session that started with OpenID Connect:

- **RP-initiated logout**: the person logs out in your application, and you
  send their browser to the provider so their session there ends too
  (`Cbox\Oidc\Logout\LogoutFlow`).
- **Token revocation**: you tell the provider to forget the refresh token
  (`Cbox\Oidc\Tokens\TokenRevocation`, RFC 7009).
- **Back-channel logout**: the provider tells you, server to server, that the
  person's session there ended, and you end yours (OpenID Connect Back-Channel
  Logout 1.0).

Front-channel logout is not supported.

## Logging out

End your own session first, then revoke and redirect:

<!-- example: logout-route -->
```php
<?php

use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Logout\LogoutFlow;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Tokens\TokenRevocation;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware('web')->post('/logout', function (Request $request, LogoutFlow $logout, TokenRevocation $revocation): RedirectResponse {
    $idToken = $request->session()->get('oidc.id_token');
    $refreshToken = $request->session()->get('oidc.refresh_token');

    // Auth::logout() here, in an application with a guard.
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    if (is_string($refreshToken) && $revocation->supported()) {
        try {
            $revocation->revoke($refreshToken);
        } catch (OidcException $exception) {
            // The local session is over either way.
            report($exception);
        }
    }

    // To the provider's end_session_endpoint, or home when it has none.
    return $logout->redirect(options: new LogoutOptions(idTokenHint: is_string($idToken) ? $idToken : null), fallback: '/');
});
```

### RP-initiated logout

`LogoutFlow::start($connection, $options)` returns a `LogoutRequest`, the URL
of the provider's `end_session_endpoint` (return it from a route to
redirect). `redirect($connection, $options, $fallback)` returns the redirect
directly, to `$fallback` when the provider has no endpoint; Google has none.
`supported($connection)` tells which, and `start()` fails with
`oidc_endpoint_not_supported` without one.

The request carries `client_id` and, from `LogoutOptions`:

| Option | Sent as | Note |
|---|---|---|
| `idTokenHint` | `id_token_hint` | The ID token of the login (`$result->tokens->idToken`). Recommended: the provider then knows whose session to end. |
| `postLogoutRedirectUri` | `post_logout_redirect_uri` | Replaces the connection's `post_logout_redirect_uri`. Register it at the provider. |
| `state` | `state` | Returned to the post-logout redirect. |
| `logoutHint` | `logout_hint` | Such as the account's email address. |
| `uiLocales` | `ui_locales` | Language tags, in order of preference. |

A wrong option fails where it is written, with `oidc_logout_options_invalid`.
The URL keeps the endpoint's own query and must pass the SSRF guard's
redirect check (https, not a private address).

### Revocation

`TokenRevocation::revoke($token, $hint, $connection)` posts the token to the
provider's `revocation_endpoint` with the connection's client authentication.
`$hint` is a `TokenTypeHint` (`RefreshToken` by default, `AccessToken`, or
null for none). Revoking the refresh token usually ends the grant, the
access tokens issued from it included.

- 200 means revoked, also for a token the provider did not know (RFC 7009 2.2).
- An OAuth error fails with `RevocationRejected` (`oidc_revocation_rejected`),
  whose `error()` is the code, such as `unsupported_token_type`.
- 503 and other temporary failures fail with `ProviderUnavailable`; retry
  later, for example from a queued job.
- Without a `revocation_endpoint` it fails with `oidc_endpoint_not_supported`;
  ask `supported($connection)` first.

## Back-channel logout

The provider posts a logout token to an endpoint of yours when the person's
session there ends. Register the endpoint with the route macro, outside the
`web` group (it needs no session, and the macro turns CSRF verification off
for it), for example in `routes/api.php`, and register its URL at the
provider:

<!-- example: backchannel-logout -->
```php
<?php

use Cbox\Oidc\Events\BackChannelLogoutReceived;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;

// The provider posts logout tokens here, e.g. /oidc/main/backchannel-logout.
Route::oidcBackChannelLogout('oidc/{connection}/backchannel-logout');

// Remember when each provider session ended: by sid when the token names
// one, else every session of the subject.
$key = fn (string $issuer, string $id): string => 'oidc-ended:'.hash('sha256', $issuer."\n".$id);

Event::listen(function (BackChannelLogoutReceived $event) use ($key): void {
    $token = $event->token;
    $id = $token->sessionId ?? 'sub:'.$token->subject;

    Cache::put($key($token->issuer, $id), $token->issuedAt->getTimestamp(), now()->addDays(30));
});

// On each request, sign out a session whose provider session ended. A login
// after the logout has a newer ID token, so it stays.
Route::middleware('web')->get('/account', function (Request $request) use ($key): RedirectResponse|JsonResponse {
    $claims = $request->session()->get('oidc.claims');

    if (! $claims instanceof VerifiedClaims) {
        return redirect('/login');
    }

    foreach ([$claims->sessionId, 'sub:'.$claims->subject] as $id) {
        $endedAt = $id === null ? null : Cache::get($key($claims->issuer, $id));

        if (is_int($endedAt) && $claims->issuedAt->getTimestamp() <= $endedAt) {
            $request->session()->invalidate();

            return redirect('/login');
        }
    }

    return response()->json(['subject' => $claims->subject]);
});
```

`Route::oidcBackChannelLogout($uri, $connection)` registers a POST route to
`Cbox\Oidc\Routing\BackChannelLogoutController`, named
`oidc.backchannel-logout`. Put `{connection}` in the URI, or pass
`$connection` for a route of one connection (then named
`oidc.backchannel-logout.<connection>`). The controller reads `logout_token`
from the form body, verifies it, dispatches `BackChannelLogoutReceived` and
answers:

| Status | When |
|---|---|
| 200 | The token verified and every listener returned. |
| 400 | No `logout_token`, or the token was refused; the body is an OAuth error whose description names the code, and the refusal is logged as a warning. |
| 404 | The connection is not configured. |
| 503 | The provider's keys or discovery document cannot be loaded now; logged as an error, so the provider can retry. |
| 500 | A listener threw. The token's `jti` is given back, so a retry is not taken for a replay. |

`BackChannelLogoutReceived::$token` is a `LogoutToken`: `connection`,
`issuer`, `subject` (null when the token has only a `sid`), `sessionId` (the
`sid`, null when it has only a `sub`), `jti`, `issuedAt`, `expiresAt` and
`claim()`. `matches($claims)` tells whether the session that signed in with
`VerifiedClaims` `$claims` is one it ends; use it when you hold the claims of
a session in hand. Ending sessions of other people needs an index you keep,
such as the cache keys above or a table of session ids by `sid`.

### The rules a logout token must pass

`Cbox\Oidc\Logout\LogoutTokenVerifier::verify($connection, $token)` checks,
in order; the first rule a token breaks throws a `TokenRejected` with its own
code:

| # | Rule | Code |
|---|---|---|
| 1 | Form, header, `alg`, key and signature as for an [ID token](id-token-verification.md). `typ` is `logout+jwt`, `application/logout+jwt`, `JWT` or absent. | as for an ID token, `oidc_token_type_invalid` |
| 2 | `iss`, `aud` and `azp`, `exp` (required), `nbf` and `iat` (at most `max_token_age_seconds` old), as for an ID token. | as for an ID token |
| 3 | `events` is a JSON object with the member `http://schemas.openid.net/event/backchannel-logout`, whose value is a JSON object. | `oidc_logout_token_invalid` |
| 4 | There is no `nonce`, so an ID token can never pass as a logout token. | `oidc_logout_token_invalid` |
| 5 | `sub`, `sid` or both are present, each 1 to 255 characters. | `oidc_logout_token_invalid`, `oidc_token_claim_invalid` |
| 6 | `jti` is present, 1 to 255 characters. | `oidc_logout_token_invalid` |
| 7 | The `jti` was not accepted before. | `oidc_logout_token_replayed` |

Rules 3 to 7 throw `LogoutTokenRejected`, a `TokenRejected`. The `jti` is
remembered in the cache store of `oidc.cache.store` until the token's `exp`
plus the leeway; every server must share that store (redis, database or
memcached), or each remembers only its own. It is checked last, so a token
refused for another reason does not use up its `jti`.

For a Microsoft Entra `{tenantid}` connection, a logout token must carry
`tid` so its issuer can be checked; the tenant allow-list is not applied to
logout tokens, which end sessions rather than start them.

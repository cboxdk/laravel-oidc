---
title: Checking a connection
description: Run php artisan oidc:check to see whether a connection can sign people in, and why not
weight: 13
---

# Checking a connection

```bash
php artisan oidc:check            # the default connection
php artisan oidc:check google     # one connection
php artisan oidc:check --all      # every connection
php artisan oidc:check --json     # a report for scripts
```

The command fetches the connection's discovery document and key set afresh,
through the same HTTP client, SSRF guard and checks as a login. It leaves the
cache alone, so a provider that is down during a check keeps serving logins
from the cached copies. It prints one line per check, here for the connection of the
[quickstart](../quickstart.md):

<!-- example: oidc-check-output -->
```text
  Connection main

  PASS  configuration  Issuer https://login.example.com, client your-client-id, client_auth client_secret_basic.
  PASS  discovery      https://login.example.com/.well-known/openid-configuration names the pinned issuer https://login.example.com.
  PASS  algorithms     ID tokens may be signed with RS256.
  PASS  keys           2 of the 2 keys at https://login.example.com/oauth/jwks may verify ID tokens.
  PASS  userinfo       Userinfo is at https://login.example.com/oauth/userinfo.
  PASS  logout         RP-initiated logout goes to https://login.example.com/oauth/logout.
  NOTE  revocation     The provider has no revocation_endpoint; Oidc::revoke() is not available.
  NOTE  back-channel   The provider does not announce back-channel logout (backchannel_logout_supported).
  PASS  iss parameter  The provider announces the iss callback parameter (RFC 9207); a callback without it is refused.

  Connection main can sign people in.
```

| Check | Fails or warns when |
|---|---|
| `configuration` | A value of `config/oidc.php` is invalid, or the connection is not configured. |
| `redirect_uri` | Warns: the redirect URI is http on a host other than `localhost`, `127.0.0.1`, `*.localhost` or `*.test`. |
| `client_assertion` | Warns: another connection signs its `private_key_jwt` assertions with the same key. |
| `tenant` | Warns: the tenant policy accepts any tenant (`['*']`). |
| `discovery` | The document cannot be fetched, names another issuer, or cannot work with the connection (no common algorithm, no PKCE S256, not the connection's client authentication). |
| `algorithms` | Lists the algorithms ID tokens may be signed with: the connection's that the provider also lists. |
| `keys` | No key of the key set may verify a token with those algorithms. Warns when several usable keys lack a `kid`. |
| `userinfo` | The connection reads groups from userinfo, and the provider has no userinfo endpoint. |
| `logout`, `revocation`, `back-channel`, `iss parameter` | Never fail; a note says what the provider does not offer. |

A failed check prints the [error code](../core-concepts/errors.md) a login
would fail with, and the fix. The command exits 1 when a check fails, so it
fits a deploy step or a health check; warnings and notes exit 0. Checks that
need an earlier one (discovery needs the configuration, the keys need
discovery) are left out when that one fails.

`--json` prints `{"connections": [{"connection", "passed", "findings": [{"status", "check", "message", "fix", "code"}]}]}`,
with `status` one of `pass`, `note`, `warn` and `fail`.

## What it does not check

- The client secret or private key: the token endpoint is only called with a
  code from a real login. A wrong secret fails the first login with
  `oidc_token_request_rejected` and `error()` `invalid_client`.
- The redirect URI registered at the provider: only the provider knows it. A
  mismatch shows on the provider's page during the first login.

The same checks are available in code, as
`Cbox\Oidc\Diagnostics\ConnectionDiagnostics::diagnose($connection)`, which
returns a `Diagnosis` of `Finding`s.

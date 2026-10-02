---
title: Security
description: Reporting vulnerabilities, and what the package does and does not protect
weight: 30
---

# Security

## Reporting

Report vulnerabilities privately through
[GitHub Private Vulnerability Reporting](https://github.com/cboxdk/laravel-oidc/security/advisories/new),
as [SECURITY.md](../../SECURITY.md) describes. Token verification bypasses are
the class of report we most want.

## What the configuration already prevents

- `alg: none` and the `HS*` algorithms cannot be configured for ID tokens.
- The issuer must be https, without a query or fragment, so it can be compared
  exactly with the provider's metadata.
- A Microsoft Entra issuer template (`{tenantid}`) cannot be configured without
  a tenant policy on `tid`; accepting any tenant takes an explicit `['*']`.
- Protocol parameters the package sets itself (`state`, `nonce`, the PKCE
  challenge, `redirect_uri` and others) cannot be overridden through
  `authorization_parameters`.
- The client secret is redacted when a connection is dumped.

## What the HTTP layer prevents

- Every call to a provider, including the URLs a discovery document names,
  passes the `cboxdk/laravel-ssrf` guard: https only, and no private, loopback
  or metadata address. The guard checks the URL actually sent and pins the
  resolved address.
- Redirects are never followed, and bodies are capped at
  `oidc.http.max_response_bytes`.
- A discovery document must name exactly the configured issuer, and every
  endpoint in it must be https.
- JSON with the same key twice is refused, so the package and the provider
  cannot read one document two ways.
- Keys come from the provider's key set only. Header members that carry or
  point to a key (`jwk`, `jku`, `x5u`, `x5c`) are never used, a key must fit
  the algorithm (type, curve, at least 2048-bit RSA, EC points on the curve),
  and an unknown `kid` refetches the key set at most once per cooldown.

## What the login flow prevents

- **Login CSRF and injected codes.** Every login gets a fresh 256-bit state,
  kept server-side under its SHA-256 and compared in constant time. A callback
  is accepted only for a login this session started for this connection, once,
  and within `oidc.flow.transaction_ttl_seconds`. The state is checked before
  anything else, so a forged code or error is refused without a call to the
  provider.
- **Stolen codes.** PKCE with S256 is always sent, also by confidential
  clients; the verifier never leaves the server except to the token endpoint.
- **Replayed ID tokens.** A fresh nonce per login is kept for the ID token
  check.
- **Mix-up attacks.** Each connection has its own callback, and the `iss`
  parameter (RFC 9207) must be the pinned issuer whenever the callback carries
  it or the provider announces it.
- **Injected text.** Only the OAuth error code of an error answer is read, and
  only when it is letters, digits, dots, dashes and underscores;
  `error_description` never reaches a message, log or page.
- **Open redirects.** The authorization URL is built from the checked
  discovery document and passes the SSRF guard's redirect check.
- Tokens, the nonce, the PKCE verifier and private keys are redacted when
  dumped.

## Honest scope

- The package is a relying party. It issues no tokens.
- Encrypted ID tokens (JWE), signed userinfo, pushed authorization requests
  (PAR), DPoP and the form_post response mode are not part of 0.1.
  Front-channel logout is not supported.
- The default transaction store trusts the Laravel session. A session that
  cannot reach the callback (a `SameSite=strict` cookie) makes every login
  fail closed with `oidc_state_mismatch`.
- The SSRF guard is defence in depth; a network egress allow-list is the only
  complete control.

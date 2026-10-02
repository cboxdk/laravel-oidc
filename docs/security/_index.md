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

## Honest scope

- The package is a relying party. It issues no tokens.
- Encrypted ID tokens (JWE), signed userinfo and `private_key_jwt` client
  authentication are not part of 0.1. Front-channel logout is not supported.
- The SSRF guard is defence in depth; a network egress allow-list is the only
  complete control.

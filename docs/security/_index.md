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

## Honest scope

- The package is a relying party. It issues no tokens.
- Encrypted ID tokens (JWE), signed userinfo and `private_key_jwt` client
  authentication are not part of 0.1. Front-channel logout is not supported.
- The SSRF guard is defence in depth; a network egress allow-list is the only
  complete control.

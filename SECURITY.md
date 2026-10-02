# Security Policy

`cboxdk/laravel-oidc` decides who is signed in to your application, so a flaw
here is high impact.

## Reporting a vulnerability

**Do not open a public issue.** Report privately via
[GitHub Private Vulnerability Reporting](https://github.com/cboxdk/laravel-oidc/security/advisories/new)
(repository → **Security** → **Report a vulnerability**). This is a best-effort
open-source project with no funded security team and no response-time guarantee;
we'll respond as promptly as we can and coordinate disclosure with you. Good-faith
research under this policy is authorized (safe harbor).

The reports we most want to see are **token verification bypasses**: an ID
token, logout token or callback that the package accepts although it should not.
For example a token signed with an algorithm the connection does not allow, by a
key the provider did not publish, for another audience, issuer or tenant, with a
wrong or replayed nonce, or a logout token that can be replayed. Please include
the token (or how to build it), the connection configuration and the provider.

## Scope reminder

The package verifies tokens with `web-token/jwt-library` and checks the protocol
rules on top. A vulnerability in that library is reported upstream; we pin a
fixed version once one exists. Outbound calls go through `cboxdk/laravel-ssrf`,
which is defence in depth, not a complete fix for SSRF. See the "Honest scope"
section of the [README](README.md).

## Supported versions

The package is not released yet. Once it is, security fixes target the latest
minor release only.

---
title: Providers
description: A tested configuration and the quirks of each common OpenID provider
weight: 40
---

# Providers

Each page fills in the connection `main` of the published `config/oidc.php`:
the same `OIDC_*` variables in `.env` as the [quickstart](../quickstart.md),
with the redirect URI `https://app.example.com/oidc/callback` that its routes
serve. Where a provider needs more than the defaults, the page shows the keys
to set in `connections.main` (publish the file first with
`php artisan vendor:publish --tag=oidc-config`). The test suite signs in
through every page's settings against an in-process provider shaped like the
real one, so they stay valid.

Whatever the provider, `php artisan oidc:check` fetches its discovery
document and keys and tells you what it supports. See
[checking a connection](../getting-started/checking-a-connection.md).

- **[Google](google.md)** — Google accounts and Google Workspace, pinned to your domains
- **[Microsoft Entra ID](microsoft-entra.md)** — One tenant, or several tenants with an allow-list
- **[Okta](okta.md)** — The default custom authorization server or the org authorization server
- **[Keycloak](keycloak.md)** — A realm, with groups and back-channel logout, and a local Keycloak in Docker
- **[Auth0](auth0.md)** — A tenant, with the trailing slash its issuer has
- **[Cbox ID](cbox-id.md)** — A Cbox ID instance

To sign in through two providers, add a second connection next to `main`
with its own variables and its own callback URL (two connections never share
one); [the login flow](../core-concepts/login-flow.md#routes) has routes for
several connections.

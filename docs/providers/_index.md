---
title: Providers
description: A tested configuration and the quirks of each common OpenID provider
weight: 40
---

# Providers

Each page has a complete `config/oidc.php` for the provider and what to set up
on the provider's side. The test suite signs in through every configuration
below against an in-process provider shaped like the real one, so the
configurations stay valid.

Whatever the provider, `php artisan oidc:check <connection>` fetches its
discovery document and keys and tells you what it supports. See
[checking a connection](../getting-started/checking-a-connection.md).

- **[Google](google.md)** — Google accounts and Google Workspace, pinned to your domains
- **[Microsoft Entra ID](microsoft-entra.md)** — One tenant, or several tenants with an allow-list
- **[Okta](okta.md)** — The default custom authorization server or the org authorization server
- **[Keycloak](keycloak.md)** — A realm, with groups and back-channel logout
- **[Auth0](auth0.md)** — A tenant, with the trailing slash its issuer has
- **[Cbox ID](cbox-id.md)** — A Cbox ID instance

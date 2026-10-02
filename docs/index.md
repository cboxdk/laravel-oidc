---
title: Cbox OIDC
description: An OpenID Connect relying party for Laravel, with typed configuration and full ID token verification
weight: 1
---

# Cbox OIDC

`cboxdk/laravel-oidc` signs people in to a Laravel application through an
OpenID provider: Microsoft Entra ID, Google Workspace, Okta, Keycloak, Auth0,
Cbox ID or any other provider that implements OpenID Connect.

> **Status: in development, not released.** Today the package has its typed,
> multi-connection configuration and service provider. The login flow and token
> verification land in the next slices of 0.1.

## The mental model

- A **connection** is one client registered at one provider, pinned to one
  issuer (and, where the provider has tenants, to the tenants you accept). An
  application can have several, each with a name.
- The package checks every value of a connection when it first needs it. A
  connection that would make a login weaker than configured, such as one that
  allows `alg: none`, cannot be configured at all.
- Cryptography comes from `web-token/jwt-library`; the package adds the
  OpenID Connect protocol rules on top.
- Every call to a provider goes through the SSRF guard of
  `cboxdk/laravel-ssrf`.

## Read next

- [Requirements](requirements.md): PHP, Laravel and extensions
- [Quickstart](quickstart.md): configure a first connection
- [Installation](getting-started/installation.md)
- [Configuration reference](configuration/reference.md): every key and its rule
- [Security](security/_index.md): reporting and honest scope

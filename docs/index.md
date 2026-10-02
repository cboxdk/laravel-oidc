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
> multi-connection configuration, and fetches, checks and caches each
> provider's discovery document and signing keys, and runs the authorization
> code flow up to the code exchange. ID token verification lands in the next
> slice of 0.1.

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
- [Discovery and keys](core-concepts/discovery-and-keys.md): how the package learns about a provider
- [The login flow](core-concepts/login-flow.md): the routes, the options and what each step checks
- [Errors](core-concepts/errors.md): every error code and whether a retry helps
- [HTTP client and clock](extension-points/http-client.md): what you can rebind
- [Transaction store](extension-points/transaction-store.md): keep started logins somewhere other than the session
- [Security](security/_index.md): reporting and honest scope

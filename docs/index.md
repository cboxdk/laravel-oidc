---
title: Cbox OIDC
description: An OpenID Connect relying party for Laravel, with typed configuration and full ID token verification
weight: 1
---

# Cbox OIDC

`cboxdk/laravel-oidc` signs people in to a Laravel application through an
OpenID provider: Microsoft Entra ID, Google Workspace, Okta, Keycloak, Auth0,
Cbox ID or any other provider that implements OpenID Connect.

> **Status: in development, not released.** Version 0.1 is complete in
> scope and being reviewed before its first release.

<!-- example: index-routes -->
```php
<?php

use Cbox\Oidc\Facades\Oidc;
use Illuminate\Support\Facades\Route;

Route::get('/login', fn () => Oidc::redirect());
Route::get('/oidc/callback', fn () => Oidc::callback()->claims->subject);
```

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
- The `Oidc` facade is the front; `Oidc::fake()` replaces it in your tests,
  and `php artisan oidc:check` tells you whether a connection works.

## Read next

- [Requirements](requirements.md): PHP, Laravel and extensions
- [Quickstart](quickstart.md): sign people in, in a few lines, and test it
- [Installation](getting-started/installation.md)
- [Testing](getting-started/testing.md): `Oidc::fake()` and its assertions
- [Checking a connection](getting-started/checking-a-connection.md): `php artisan oidc:check`
- [Providers](providers/_index.md): Google, Microsoft Entra ID, Okta, Keycloak, Auth0 and Cbox ID
- [The Oidc facade](core-concepts/the-oidc-facade.md): every call, and several connections
- [Configuration reference](configuration/reference.md): every key and its rule
- [Discovery and keys](core-concepts/discovery-and-keys.md): how the package learns about a provider
- [The login flow](core-concepts/login-flow.md): the routes, the options and what each step checks
- [ID token verification](core-concepts/id-token-verification.md): every rule, tenant pinning and the verified claims
- [Refresh and userinfo](core-concepts/refresh-and-userinfo.md): renew tokens and read the person's claims
- [Logout](core-concepts/logout.md): RP-initiated logout, revocation and back-channel logout
- [Errors](core-concepts/errors.md): every error code and whether a retry helps
- [HTTP client and clock](extension-points/http-client.md): what you can rebind
- [Transaction store](extension-points/transaction-store.md): keep started logins somewhere other than the session
- [Security](security/_index.md): reporting and honest scope

---
title: Installation
description: Install the package, publish the configuration and set the environment
weight: 11
---

# Installation

```bash
composer require cboxdk/laravel-oidc
```

Laravel discovers `Cbox\Oidc\OidcServiceProvider` on its own and merges the
default configuration, so for one provider, setting `.env` is enough.
Publish the configuration when you need to change more than the environment
gives you, such as a second connection, a tenant pin or extra scopes:

```bash
php artisan vendor:publish --tag=oidc-config
```

This writes `config/oidc.php`. Its connection `main` reads the environment
variables `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`,
`OIDC_REDIRECT_URI` and, optionally, `OIDC_DISCOVERY_URL` and
`OIDC_POST_LOGOUT_REDIRECT_URI`, and `OIDC_ALLOW_INSECURE_HTTP` for a provider
on your own machine. `OIDC_CONNECTION` picks the default connection.

The package parses the configuration on first use, not at boot, so an
application that installed it but has not configured it yet keeps booting. The
first OIDC call then names the missing key.

Laravel also registers the `Oidc` facade alias and the `oidc:check` command.

Next: the [configuration reference](../configuration/reference.md), the page
of [your provider](../providers/_index.md), and
[checking a connection](checking-a-connection.md).

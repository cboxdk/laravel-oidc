---
title: Quickstart
description: Install the package and configure a first connection
weight: 2
---

# Quickstart

Install the package and publish its configuration:

```bash
composer require cboxdk/laravel-oidc
php artisan vendor:publish --tag=oidc-config
```

Register your application at the provider with the redirect URI
`https://app.example.com/oidc/callback`, and put what it gives you in `.env`:

```dotenv
OIDC_ISSUER=https://login.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
```

The published `config/oidc.php` reads these into the connection `main`. To
check the configuration, resolve it once, for example in `php artisan tinker`:

```php
use Cbox\Oidc\Config\OidcConfig;

$connection = app(OidcConfig::class)->connection();

$connection->issuer;       // 'https://login.example.com'
$connection->discoveryUrl; // 'https://login.example.com/.well-known/openid-configuration'
```

A missing or wrong value throws `InvalidConfiguration`, which names the key and
the fix.

To check that the package can reach the provider, fetch its discovery
document:

```php
use Cbox\Oidc\Discovery\MetadataRepository;

app(MetadataRepository::class)->for($connection)->tokenEndpoint;
```

An issuer that does not match the document, or a provider the SSRF guard
refuses, fails here with a [coded error](core-concepts/errors.md).

Then add a login route and a callback route; [the login flow](core-concepts/login-flow.md)
has a complete, tested example. The callback exchanges the code, verifies the
ID token and returns its verified claims; sign the person in by
`$result->claims->issuer` and `$result->claims->subject`.

To keep a session alive past the access token's lifetime, see
[refresh and userinfo](core-concepts/refresh-and-userinfo.md); to log out at
the provider too, and to receive its back-channel logout, see
[logout](core-concepts/logout.md).

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

The login routes and the verified result arrive with the next slices of 0.1.

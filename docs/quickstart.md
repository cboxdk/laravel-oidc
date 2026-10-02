---
title: Quickstart
description: Sign people in through an OpenID provider in a few lines, and test it
weight: 2
---

# Quickstart

## 1. Install

```bash
composer require cboxdk/laravel-oidc
php artisan vendor:publish --tag=oidc-config
```

## 2. Register your application at the provider

Register a web application with the redirect URI
`https://app.example.com/oidc/callback`, and put what the provider gives you
in `.env`:

```dotenv
OIDC_ISSUER=https://login.example.com
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
```

The published `config/oidc.php` reads these into the connection `main`. The
[provider pages](providers/_index.md) have a tested configuration for Google,
Microsoft Entra ID, Okta, Keycloak, Auth0 and Cbox ID.

## 3. Check the connection

```bash
php artisan oidc:check
```

It fetches the provider's discovery document and keys and prints what works,
and the fix for what does not. See
[checking a connection](getting-started/checking-a-connection.md).

## 4. Remember who signed in

A person is identified by the provider's issuer and their subject there,
never by email. Add both to the users table, and let the password be empty:

<!-- example: setup-migration -->
```php
<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->string('oidc_issuer')->nullable();
            $table->string('oidc_subject')->nullable();
            $table->string('password')->nullable()->change();
            $table->unique(['oidc_issuer', 'oidc_subject']);
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table): void {
            $table->dropUnique(['oidc_issuer', 'oidc_subject']);
            $table->dropColumn(['oidc_issuer', 'oidc_subject']);
        });
    }
};
```

Add the two columns to the model's `$fillable`:

<!-- example: setup-model -->
```php
<?php

namespace App\Models;

use Illuminate\Foundation\Auth\User as Authenticatable;

class User extends Authenticatable
{
    protected $fillable = ['name', 'email', 'password', 'oidc_issuer', 'oidc_subject'];
}
```

## 5. Add the routes

In `routes/web.php`:

<!-- example: setup-routes -->
```php
<?php

use App\Models\User;
use Cbox\Oidc\Facades\Oidc;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::get('/login', fn () => Oidc::redirect())->name('login');

Route::get('/oidc/callback', function () {
    $claims = Oidc::callback()->claims;

    Auth::login(User::updateOrCreate(
        ['oidc_issuer' => $claims->issuer, 'oidc_subject' => $claims->subject],
        ['name' => $claims->name() ?? $claims->subject, 'email' => $claims->email()],
    ));
    session()->regenerate();

    return redirect()->intended('/');
});
```

`Oidc::redirect()` sends the browser to the provider with a fresh state, nonce
and PKCE challenge. `Oidc::callback()` checks the browser's return, exchanges
the code and verifies the ID token; `$claims` are the verified claims.

A failed login throws an `OidcException` with a code and a fix. Unhandled, it
is a 500 page; [the login flow](core-concepts/login-flow.md#routes) shows the
routes with error handling, which you want before going live. Your users table
must accept a null email if the provider may not send one.

## 6. Test it

`Oidc::fake()` replaces the provider in your tests:

<!-- example: setup-test -->
```php
<?php

use App\Models\User;
use Cbox\Oidc\Facades\Oidc;

it('signs a person in through the provider', function () {
    Oidc::fake()->signIn('user-1', ['email' => 'ada@example.com', 'name' => 'Ada Lovelace']);

    $this->get('/login')->assertRedirect();
    $this->get('/oidc/callback')->assertRedirect('/');

    $this->assertAuthenticatedAs(User::where('oidc_subject', 'user-1')->sole());
});
```

See [testing](getting-started/testing.md) for failed logins, refresh, logout
and back-channel logout.

## Next

- [The Oidc facade](core-concepts/the-oidc-facade.md): every call, and several connections
- [Refresh and userinfo](core-concepts/refresh-and-userinfo.md): keep a session alive past the access token
- [Logout](core-concepts/logout.md): log out at the provider, and receive its back-channel logout
- [Security](security/_index.md): what the package checks for you

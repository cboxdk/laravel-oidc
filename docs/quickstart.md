---
title: Quickstart
description: Sign people in through an OpenID provider in a few lines, and test it
weight: 2
---

# Quickstart

## 1. Install

```bash
composer require cboxdk/laravel-oidc
```

The defaults are merged in, so publishing `config/oidc.php` is optional. Do
it when you add a second connection or pin tenants:
`php artisan vendor:publish --tag=oidc-config`.

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

The connection `main` of `config/oidc.php` reads these. The
[provider pages](providers/_index.md) have the values for Google, Microsoft
Entra ID, Okta, Keycloak, Auth0 and Cbox ID.

## 3. Check the connection

```bash
php artisan oidc:check
```

It fetches the provider's discovery document and keys and prints what works,
and the fix for what does not. See
[checking a connection](getting-started/checking-a-connection.md).

## 4. Remember who signed in

A person is identified by the provider's issuer and their subject there,
never by email. Add both to the users table, and let the password and the
email be empty, because not every provider sends a verified email:

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
            $table->string('email')->nullable()->change();
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
use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\CallbackRejected;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Facades\Oidc;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Route;

Route::get('/login', fn () => Oidc::redirect())->name('login');

Route::get('/oidc/callback', function () {
    try {
        $claims = Oidc::callback()->claims;
    } catch (CallbackRejected) {
        // Reloaded, used twice or too old.
        return redirect('/')->with('status', 'Your sign-in expired. Please sign in again.');
    } catch (AuthorizationDenied|TenantRejected) {
        // Cancelled at the provider, or an organisation that may not sign in.
        return redirect('/')->with('status', 'You were not signed in.');
    } catch (OidcException $exception) {
        report($exception);

        return redirect('/')->with('status', 'Sign-in failed. Please try again.');
    }

    Auth::login(User::updateOrCreate(
        ['oidc_issuer' => $claims->issuer, 'oidc_subject' => $claims->subject],
        // An unverified address is not the person's: keep it out.
        ['name' => $claims->name() ?? $claims->subject, 'email' => $claims->emailVerified() ? $claims->email() : null],
    ));
    session()->regenerate();

    return redirect()->intended('/');
});
```

`Oidc::redirect()` sends the browser to the provider with a fresh state, nonce
and PKCE challenge. `Oidc::callback()` checks the browser's return, exchanges
the code and verifies the ID token; `$claims` are the verified claims.

A failed login throws an `OidcException` with a code and a fix. The route
handles the ones that happen in normal use: `CallbackRejected` when the person
reloads the callback, goes back to it or took longer than ten minutes,
`AuthorizationDenied` when they cancel at the provider, and `TenantRejected`
when their organisation may not sign in. Anything else is reported. See
[errors](core-concepts/errors.md) for every code.

Only a verified email is stored. `users.email` stays unique, so a person who
signs in through a second provider, or who has a password account with the
same address, makes `updateOrCreate` fail on the unique index. Decide what
that means for you: link the accounts on purpose (look the user up by the
verified email and store the issuer and subject on them), or drop the unique
index on `email`.

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

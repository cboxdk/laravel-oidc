<?php

declare(strict_types=1);

namespace Cbox\Oidc\Facades;

use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\OidcManager;
use Cbox\Oidc\Testing\OidcFake;
use Illuminate\Support\Facades\Facade;
use RuntimeException;

/**
 * The OpenID Connect calls of an application:
 *
 *     Route::get('/login', fn () => Oidc::redirect());
 *     Route::get('/oidc/callback', fn () => ... Oidc::callback()->claims ...);
 *
 * Every method takes the connection by name; null is the default.
 *
 * @method static \Cbox\Oidc\OidcConnection connection(string|null $name = null)
 * @method static \Cbox\Oidc\Flow\AuthorizationRequest start(string|null $connection = null, \Cbox\Oidc\Flow\AuthorizationOptions|null $options = null)
 * @method static \Illuminate\Http\RedirectResponse redirect(string|null $connection = null, \Cbox\Oidc\Flow\AuthorizationOptions|null $options = null)
 * @method static \Cbox\Oidc\Flow\CallbackResult callback(string|null $connection = null, \Illuminate\Http\Request|null $request = null)
 * @method static \Cbox\Oidc\Tokens\RefreshResult refresh(\Cbox\Oidc\Tokens\VerifiedClaims $claims, string $refreshToken, list<string>|null $scopes = null)
 * @method static \Cbox\Oidc\UserInfo\UserInfo userInfo(\Cbox\Oidc\Tokens\VerifiedClaims $claims, string $accessToken)
 * @method static \Illuminate\Http\RedirectResponse logout(string|null $connection = null, \Cbox\Oidc\Logout\LogoutOptions|null $options = null, string $fallback = '/')
 * @method static void revoke(string $token, \Cbox\Oidc\Tokens\TokenTypeHint|null $hint = \Cbox\Oidc\Tokens\TokenTypeHint::RefreshToken, string|null $connection = null)
 *
 * @see OidcClient
 * @see OidcManager
 */
final class Oidc extends Facade
{
    /**
     * Swaps the client for an in-memory fake with assertions, for this test.
     * Code that type-hints {@see OidcClient} gets the fake too.
     */
    public static function fake(): OidcFake
    {
        $app = self::getFacadeApplication() ?? throw new RuntimeException('Oidc::fake() needs a booted Laravel application.');
        $fake = $app->make(OidcFake::class);

        self::swap($fake);

        return $fake;
    }

    protected static function getFacadeAccessor(): string
    {
        return OidcClient::class;
    }
}

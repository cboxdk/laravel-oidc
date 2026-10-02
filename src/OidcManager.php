<?php

declare(strict_types=1);

namespace Cbox\Oidc;

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationRequest;
use Cbox\Oidc\Flow\CallbackResult;
use Cbox\Oidc\Logout\LogoutFlow;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Tokens\RefreshResult;
use Cbox\Oidc\Tokens\TokenRefresher;
use Cbox\Oidc\Tokens\TokenRevocation;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Cbox\Oidc\UserInfo\UserInfo;
use Cbox\Oidc\UserInfo\UserInfoEndpoint;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use SensitiveParameter;

/**
 * The {@see OidcClient} the {@see Facades\Oidc} facade calls: a thin front
 * over the package's services ({@see AuthorizationFlow}, {@see TokenRefresher},
 * {@see UserInfoEndpoint}, {@see LogoutFlow}, {@see TokenRevocation}), which
 * stay available for the less common calls.
 *
 * The services are resolved on each call, so an application that has not
 * configured the package yet keeps booting, and a long-running worker always
 * sees the current request.
 */
final readonly class OidcManager implements OidcClient
{
    public function __construct(private Container $container) {}

    public function connection(?string $name = null): OidcConnection
    {
        return new OidcConnection($this, $this->container->make(OidcConfig::class)->connection($name)->name);
    }

    public function start(?string $connection = null, ?AuthorizationOptions $options = null): AuthorizationRequest
    {
        return $this->container->make(AuthorizationFlow::class)->start($connection, $options ?? new AuthorizationOptions);
    }

    public function redirect(?string $connection = null, ?AuthorizationOptions $options = null): RedirectResponse
    {
        return $this->start($connection, $options)->redirect();
    }

    public function callback(?string $connection = null, ?Request $request = null): CallbackResult
    {
        return $this->container->make(AuthorizationFlow::class)->callback($request ?? $this->container->make(Request::class), $connection);
    }

    public function refresh(VerifiedClaims $claims, #[SensitiveParameter] string $refreshToken, ?array $scopes = null): RefreshResult
    {
        return $this->container->make(TokenRefresher::class)->refresh($claims, $refreshToken, $scopes);
    }

    public function userInfo(VerifiedClaims $claims, #[SensitiveParameter] string $accessToken): UserInfo
    {
        return $this->container->make(UserInfoEndpoint::class)->fetch($claims, $accessToken);
    }

    public function logout(?string $connection = null, ?LogoutOptions $options = null, string $fallback = '/'): RedirectResponse
    {
        return $this->container->make(LogoutFlow::class)->redirect($connection, $options ?? new LogoutOptions, $fallback);
    }

    public function revoke(#[SensitiveParameter] string $token, ?TokenTypeHint $hint = TokenTypeHint::RefreshToken, ?string $connection = null): void
    {
        $this->container->make(TokenRevocation::class)->revoke($token, $hint, $connection);
    }
}

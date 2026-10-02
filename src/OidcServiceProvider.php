<?php

declare(strict_types=1);

namespace Cbox\Oidc;

use Cbox\Oidc\Config\OidcConfig;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;

class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        // Parsed on first use, not at boot: an application that has installed
        // the package but not configured it yet keeps booting, and the first
        // OIDC call names the missing key.
        $this->app->singleton(
            OidcConfig::class,
            static fn (Application $app): OidcConfig => OidcConfig::fromArray($app->make(Repository::class)->get('oidc')),
        );
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/oidc.php' => $this->app->configPath('oidc.php')], 'oidc-config');
    }
}

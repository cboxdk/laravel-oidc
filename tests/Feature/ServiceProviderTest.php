<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\OidcServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;

it('binds the parsed configuration as a singleton', function (): void {
    $config = resolve(OidcConfig::class);

    expect($config)->toBe(resolve(OidcConfig::class))
        ->and($config->names())->toBe(['main', 'workspace'])
        ->and($config->connection('workspace')->tenant?->claim)->toBe('hd');
});

it('merges the package defaults under the oidc key', function (): void {
    expect(resolve(Repository::class)->get('oidc.http.timeout_seconds'))->toBe(5)
        ->and(resolve(Repository::class)->get('oidc.cache.jwks_refetch_cooldown_seconds'))->toBe(60);
});

it('publishes the config file under the oidc-config tag', function (): void {
    $paths = ServiceProvider::pathsToPublish(OidcServiceProvider::class, 'oidc-config');

    expect(array_values($paths))->toBe([config_path('oidc.php')])
        ->and(array_keys($paths)[0])->toEndWith('config/oidc.php');
});

it('boots while unconfigured and names the missing key on first use', function (): void {
    resolve(Repository::class)->set('oidc.connections.main.issuer');
    app()->forgetInstance(OidcConfig::class);

    expect(fn () => resolve(OidcConfig::class))
        ->toThrow(InvalidConfiguration::class, 'oidc.connections.main.issuer must be a non-empty string');
});

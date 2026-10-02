<?php

declare(strict_types=1);

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Http\HttpResponse;
use Cbox\Oidc\Keys\KeySetRepository;
use Cbox\Oidc\Keys\SigningKeys;
use Cbox\Oidc\OidcServiceProvider;
use Cbox\Oidc\Support\CarbonClock;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\SsrfServiceProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\ServiceProvider;
use Psr\Clock\ClockInterface;

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

it('binds a Carbon-backed PSR-20 clock that follows Laravel\'s time travel', function (): void {
    $this->travelTo(new DateTimeImmutable('2030-01-02 03:04:05', new DateTimeZone('UTC')));

    $clock = resolve(ClockInterface::class);

    expect($clock)->toBeInstanceOf(CarbonClock::class)
        ->and($clock->now()->format(DATE_ATOM))->toBe('2030-01-02T03:04:05+00:00');
});

it('keeps an application\'s own clock and HTTP client', function (): void {
    $app = $this->createApplication();
    $clock = new class implements ClockInterface
    {
        public function now(): DateTimeImmutable
        {
            return new DateTimeImmutable('@0');
        }
    };
    $client = new class implements HttpClient
    {
        public function send(HttpRequest $request): HttpResponse
        {
            return new HttpResponse(200, [], '{}');
        }
    };

    $app->instance(ClockInterface::class, $clock);
    $app->instance(HttpClient::class, $client);
    $app->register(OidcServiceProvider::class, force: true);

    expect($app->make(ClockInterface::class))->toBe($clock)
        ->and($app->make(HttpClient::class))->toBe($client);
});

it('registers the SSRF guard the HTTP client depends on', function (): void {
    expect(app()->getProvider(SsrfServiceProvider::class))->toBeInstanceOf(SsrfServiceProvider::class)
        ->and(resolve(UrlGuard::class))->toBeInstanceOf(UrlGuard::class);
});

it('builds the discovery and key services as singletons', function (string $service): void {
    expect(resolve($service))->toBe(resolve($service));
})->with([MetadataRepository::class, KeySetRepository::class, SigningKeys::class, DocumentCache::class]);

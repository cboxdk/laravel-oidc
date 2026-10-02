<?php

declare(strict_types=1);

namespace Cbox\Oidc;

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Client\ClientAssertion;
use Cbox\Oidc\Client\ClientAuthentication;
use Cbox\Oidc\Config\CacheConfig;
use Cbox\Oidc\Config\FlowConfig;
use Cbox\Oidc\Config\HttpConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Contracts\TransactionStore;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Flow\SessionTransactionStore;
use Cbox\Oidc\Http\LaravelHttpClient;
use Cbox\Oidc\Keys\KeySelector;
use Cbox\Oidc\Keys\KeySetRepository;
use Cbox\Oidc\Keys\SigningKeys;
use Cbox\Oidc\Support\CarbonClock;
use Cbox\Oidc\Tokens\TokenEndpoint;
use Cbox\Ssrf\SsrfServiceProvider;
use Illuminate\Contracts\Cache\Factory as CacheFactory;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use Psr\Clock\ClockInterface;

class OidcServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/oidc.php', 'oidc');

        // The guard every provider call goes through. Registering it here keeps
        // it in place when package discovery is off; registering twice is a
        // no-op.
        $this->app->register(SsrfServiceProvider::class);

        // Parsed on first use, not at boot: an application that has installed
        // the package but not configured it yet keeps booting, and the first
        // OIDC call names the missing key.
        $this->app->singleton(
            OidcConfig::class,
            static fn (Application $app): OidcConfig => OidcConfig::fromArray($app->make(Repository::class)->get('oidc')),
        );

        $this->app->singleton(HttpConfig::class, static fn (Application $app): HttpConfig => $app->make(OidcConfig::class)->http);
        $this->app->singleton(CacheConfig::class, static fn (Application $app): CacheConfig => $app->make(OidcConfig::class)->cache);
        $this->app->singleton(FlowConfig::class, static fn (Application $app): FlowConfig => $app->make(OidcConfig::class)->flow);

        // Both are replaceable: the application's own binding wins.
        $this->app->singletonIf(ClockInterface::class, CarbonClock::class);
        $this->app->singletonIf(HttpClient::class, LaravelHttpClient::class);
        $this->app->singletonIf(TransactionStore::class, SessionTransactionStore::class);

        $this->app->singleton(DocumentCache::class, static fn (Application $app): DocumentCache => new DocumentCache(
            $app->make(CacheFactory::class)->store($app->make(CacheConfig::class)->store),
            $app->make(ClockInterface::class),
        ));

        $this->app->singleton(MetadataRepository::class);
        $this->app->singleton(KeySetRepository::class);
        $this->app->singleton(KeySelector::class);
        $this->app->singleton(SigningKeys::class);
        $this->app->singleton(ClientAssertion::class);
        $this->app->singleton(ClientAuthentication::class);
        $this->app->singleton(TokenEndpoint::class);
        $this->app->singleton(AuthorizationFlow::class);
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/oidc.php' => $this->app->configPath('oidc.php')], 'oidc-config');
    }
}

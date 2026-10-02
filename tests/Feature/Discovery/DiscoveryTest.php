<?php

declare(strict_types=1);

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->discover = fn (string $connection = 'main'): ProviderMetadata => resolve(MetadataRepository::class)->for(resolve(OidcConfig::class)->connection($connection));
});

it('fetches the discovery document of a connection', function (): void {
    $metadata = ($this->discover)();

    expect($metadata->issuer)->toBe(FakeProvider::ISSUER)
        ->and($metadata->jwksUri)->toBe(FakeProvider::JWKS_URL)
        ->and($this->provider->discoveryRequests)->toBe(1);

    Http::assertSent(fn (Request $request): bool => $request->url() === FakeProvider::DISCOVERY_URL && $request->hasHeader('Accept', 'application/json'));
});

it('caches the document for discovery_ttl_seconds', function (): void {
    config(['oidc.cache.discovery_ttl_seconds' => 3600]);

    ($this->discover)();
    $this->travel(3599)->seconds();
    ($this->discover)();

    expect($this->provider->discoveryRequests)->toBe(1);

    $this->travel(1)->seconds();
    ($this->discover)();

    expect($this->provider->discoveryRequests)->toBe(2);
});

it('shares the cached document across processes through the cache store', function (): void {
    ($this->discover)();
    app()->forgetInstance(MetadataRepository::class);
    app()->forgetInstance(DocumentCache::class);

    ($this->discover)();

    expect($this->provider->discoveryRequests)->toBe(1);
});

it('fetches every time when discovery_ttl_seconds is 0 and stale_if_error is 0', function (): void {
    config(['oidc.cache.discovery_ttl_seconds' => 0, 'oidc.cache.stale_if_error_seconds' => 0]);

    ($this->discover)();
    ($this->discover)();

    expect($this->provider->discoveryRequests)->toBe(2);
});

it('keeps one document per connection', function (): void {
    config(['oidc.connections.second' => ConnectionFixtures::minimal(['client_id' => 'client-2', 'redirect_uri' => 'https://app.example.test/oidc/second/callback'])]);
    app()->forgetInstance(OidcConfig::class);

    ($this->discover)('main');
    ($this->discover)('second');

    expect($this->provider->discoveryRequests)->toBe(2);
});

it('forgets the cached document on request', function (): void {
    ($this->discover)();
    resolve(MetadataRepository::class)->forget(resolve(OidcConfig::class)->connection());
    ($this->discover)();

    expect($this->provider->discoveryRequests)->toBe(2);
});

it('refuses a document for another issuer and does not cache it', function (): void {
    $this->provider->discovery['issuer'] = 'https://idp.example.test/';

    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow(DiscoveryFailed::class, 'names the issuer "https://idp.example.test/", but the connection pins "https://idp.example.test"');

    $this->provider->discovery['issuer'] = FakeProvider::ISSUER;

    expect(($this->discover)()->issuer)->toBe(FakeProvider::ISSUER)
        ->and($this->provider->discoveryRequests)->toBe(2);
});

it('checks a cached document against the current configuration', function (): void {
    ($this->discover)();
    config(['oidc.connections.main.algorithms' => ['PS256']]);
    app()->forgetInstance(OidcConfig::class);

    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow(DiscoveryFailed::class, 'lists no ID token algorithm the connection accepts')
        ->and($this->provider->discoveryRequests)->toBe(1);
});

it('refuses what is not a discovery document', function (?string $body, int $status, string $exception, string $message): void {
    $this->provider->discoveryBody = $body;
    $this->provider->discoveryStatus = $status;

    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow($exception, $message);
})->with([
    'an HTML page' => ['<html>Sign in</html>', 200, InvalidProviderResponse::class, 'The discovery document from https://idp.example.test/.well-known/openid-configuration is not valid: Syntax error'],
    'a JSON list' => ['["https://idp.example.test"]', 200, InvalidProviderResponse::class, 'is not valid: the document is not a JSON object'],
    'a duplicate issuer' => ['{"issuer":"https://idp.example.test","issuer":"https://evil.example.test"}', 200, InvalidProviderResponse::class, 'is not valid: an object has the same key twice'],
    'not found' => [null, 404, InvalidProviderResponse::class, 'answered https://idp.example.test/.well-known/openid-configuration with HTTP 404'],
    'a redirect' => [null, 301, InvalidProviderResponse::class, 'with HTTP 301'],
    'a server error' => [null, 503, ProviderUnavailable::class, 'with HTTP 503, a temporary failure'],
    'rate limited' => [null, 429, ProviderUnavailable::class, 'with HTTP 429, a temporary failure'],
]);

it('says how to fix a redirecting discovery URL', function (): void {
    $this->provider->discoveryStatus = 302;

    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow(function (InvalidProviderResponse $exception): void {
        expect($exception->fix())->toContain('never follow redirects');
    });
});

it('keeps using a stale document while the provider is unavailable, for stale_if_error_seconds', function (): void {
    config(['oidc.cache.discovery_ttl_seconds' => 600, 'oidc.cache.stale_if_error_seconds' => 300]);
    ($this->discover)();
    $this->provider->discoveryStatus = 503;

    $this->travel(899)->seconds();
    expect(($this->discover)()->issuer)->toBe(FakeProvider::ISSUER);

    $this->travel(1)->seconds();
    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow(ProviderUnavailable::class);
});

it('fails at once on an outage when nothing is cached', function (): void {
    $this->provider->discoveryStatus = 500;

    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow(function (ProviderUnavailable $exception): void {
        expect($exception->errorCode())->toBe(ErrorCode::ProviderUnavailable);
    });
});

it('refuses a discovery URL the SSRF guard blocks', function (): void {
    config(['oidc.connections.main.discovery_url' => 'https://internal.example.test/.well-known/openid-configuration']);
    app()->forgetInstance(OidcConfig::class);

    expect(fn (): ProviderMetadata => ($this->discover)())->toThrow(OutboundRequestBlocked::class, 'refused a call to https://internal.example.test');
    expect($this->provider->discoveryRequests)->toBe(0);
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Cache\FetchedDocument;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Illuminate\Cache\ArrayStore;
use Illuminate\Cache\Repository;
use Psr\Clock\ClockInterface;

final class SteppedClock implements ClockInterface
{
    public function __construct(public int $now = 1_800_000_000) {}

    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('@'.$this->now);
    }
}

beforeEach(function (): void {
    $this->clock = new SteppedClock;
    $this->store = new Repository(new ArrayStore);
    $this->cache = new DocumentCache($this->store, $this->clock);
    $this->fetches = 0;
    $this->fetch = (fn (string $body = 'v1', int $lifetime = 100): Closure => function () use ($body, $lifetime): FetchedDocument {
        $this->fetches++;

        return new FetchedDocument($body, $lifetime);
    });
});

it('fetches once and serves the copy while it is fresh', function (): void {
    expect($this->cache->remember('k', 0, ($this->fetch)('v1')))->toBe('v1');

    $this->clock->now += 99;

    expect($this->cache->remember('k', 0, ($this->fetch)('v2')))->toBe('v1')
        ->and($this->fetches)->toBe(1);
});

it('fetches again once the copy is stale', function (): void {
    $this->cache->remember('k', 0, ($this->fetch)('v1'));
    $this->clock->now += 100;

    expect($this->cache->remember('k', 0, ($this->fetch)('v2')))->toBe('v2')
        ->and($this->fetches)->toBe(2);
});

it('uses a stale copy while the provider is unavailable, within stale_if_error', function (): void {
    $this->cache->remember('k', 50, ($this->fetch)('v1'));
    $unavailable = fn (): FetchedDocument => throw ProviderUnavailable::status('https://idp.example.test/keys', 503);

    $this->clock->now += 149;
    expect($this->cache->remember('k', 50, $unavailable))->toBe('v1');

    $this->clock->now += 1;
    expect(fn (): string => $this->cache->remember('k', 50, $unavailable))->toThrow(ProviderUnavailable::class);
});

it('never replaces a wrong document with a stale copy', function (): void {
    $this->cache->remember('k', 50, ($this->fetch)('v1'));
    $this->clock->now += 120;

    expect(fn (): string => $this->cache->remember('k', 50, fn (): FetchedDocument => throw InvalidProviderResponse::status('https://idp.example.test/keys', 404)))
        ->toThrow(InvalidProviderResponse::class);
});

it('fetches when forced, and does not fall back to the copy then', function (): void {
    $this->cache->remember('k', 50, ($this->fetch)('v1'));

    expect($this->cache->remember('k', 50, ($this->fetch)('v2'), refresh: true))->toBe('v2')
        ->and(fn (): string => $this->cache->remember('k', 50, fn (): FetchedDocument => throw ProviderUnavailable::status('https://idp.example.test/keys', 503), refresh: true))
        ->toThrow(ProviderUnavailable::class);
});

it('stores the copy in the shared cache for its lifetime plus stale_if_error', function (): void {
    $this->cache->remember('k', 50, ($this->fetch)('v1', 100));

    expect($this->store->get('k'))->toBe(['body' => 'v1', 'fetched_at' => 1_800_000_000, 'fresh_until' => 1_800_000_100]);
});

it('stores nothing when neither lifetime nor stale_if_error is set', function (): void {
    $this->store->put('k', ['body' => 'old', 'fetched_at' => 1, 'fresh_until' => 2], 60);

    expect($this->cache->remember('k', 0, ($this->fetch)('v1', 0)))->toBe('v1')
        ->and($this->store->get('k'))->toBeNull()
        ->and($this->cache->remember('k', 0, ($this->fetch)('v2', 0)))->toBe('v2');
});

it('picks up a newer copy another process stored', function (): void {
    $this->cache->remember('k', 0, ($this->fetch)('v1'));
    $this->clock->now += 100;
    $this->store->put('k', ['body' => 'other', 'fetched_at' => $this->clock->now, 'fresh_until' => $this->clock->now + 100], 100);

    expect($this->cache->remember('k', 0, ($this->fetch)('v2')))->toBe('other')
        ->and($this->fetches)->toBe(1);
});

it('rereads the shared cache after forgetLocal', function (): void {
    $this->cache->remember('k', 0, ($this->fetch)('v1'));
    $this->store->put('k', ['body' => 'other', 'fetched_at' => $this->clock->now + 1, 'fresh_until' => $this->clock->now + 100], 100);

    expect($this->cache->remember('k', 0, ($this->fetch)('v2')))->toBe('v1');

    $this->cache->forgetLocal('k');

    expect($this->cache->remember('k', 0, ($this->fetch)('v2')))->toBe('other');
});

it('ignores a cache entry of another shape', function (): void {
    $this->store->put('k', 'not an entry', 60);

    expect($this->cache->remember('k', 0, ($this->fetch)('v1')))->toBe('v1');
});

it('forgets both copies', function (): void {
    $this->cache->remember('k', 0, ($this->fetch)('v1'));
    $this->cache->forget('k');

    expect($this->store->get('k'))->toBeNull()
        ->and($this->cache->remember('k', 0, ($this->fetch)('v2')))->toBe('v2');
});

it('claims a slot once per window', function (): void {
    expect($this->cache->claim('slot', 60))->toBeTrue()
        ->and($this->cache->claim('slot', 60))->toBeFalse()
        ->and($this->cache->claim('other', 60))->toBeTrue();
});

it('stops serving a document another process forgot within a few seconds', function (): void {
    // Two long-lived workers (Octane, queue) share one store.
    $worker = new DocumentCache($this->store, $this->clock);
    $console = new DocumentCache($this->store, $this->clock);

    expect($worker->remember('jwks', 0, ($this->fetch)('compromised', 86400)))->toBe('compromised');

    $console->forget('jwks');

    $this->clock->now += DocumentCache::LOCAL_SECONDS - 1;
    expect($worker->remember('jwks', 0, ($this->fetch)('rotated', 86400)))->toBe('compromised');

    $this->clock->now += 1;
    expect($worker->remember('jwks', 0, ($this->fetch)('rotated', 86400)))->toBe('rotated')
        ->and($this->fetches)->toBe(2);
});

it('does not fall back to a copy another process forgot while the provider is down', function (): void {
    $worker = new DocumentCache($this->store, $this->clock);
    $worker->remember('jwks', 86400, ($this->fetch)('compromised', 10));
    new DocumentCache($this->store, $this->clock)->forget('jwks');

    $this->clock->now += 20;

    expect(fn (): string => $worker->remember('jwks', 86400, fn (): FetchedDocument => throw ProviderUnavailable::status('https://idp.example.test/keys', 503)))
        ->toThrow(ProviderUnavailable::class);
});

it('picks up a newer copy another process stored while its own is still fresh', function (): void {
    $worker = new DocumentCache($this->store, $this->clock);
    $other = new DocumentCache($this->store, $this->clock);

    $worker->remember('k', 0, ($this->fetch)('v1', 1000));
    $this->clock->now += 1;
    $other->remember('k', 0, ($this->fetch)('v2', 1000), refresh: true);

    $this->clock->now += DocumentCache::LOCAL_SECONDS;

    expect($worker->remember('k', 0, ($this->fetch)('v3', 1000)))->toBe('v2')
        ->and($this->fetches)->toBe(2);
});

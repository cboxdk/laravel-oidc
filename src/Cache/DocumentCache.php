<?php

declare(strict_types=1);

namespace Cbox\Oidc\Cache;

use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Closure;
use Illuminate\Contracts\Cache\Repository;
use Psr\Clock\ClockInterface;

/**
 * Caches provider documents (discovery, key sets) in the application's cache
 * store, with a copy per process so one request reads the store once.
 *
 * Freshness is decided by the package clock. When a refetch of a stale
 * document fails because the provider is unavailable, the stale copy is used
 * for up to stale_if_error seconds more (as HTTP's stale-if-error), so a
 * provider blip does not stop every login. A document the provider serves
 * wrongly is never replaced by a stale copy: that fails at once.
 *
 * @internal
 */
final class DocumentCache
{
    /** @var array<string, CachedDocument> */
    private array $memo = [];

    public function __construct(
        private readonly Repository $store,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * The body under $key, from the cache while fresh, else from $fetch.
     *
     * @param  Closure(): FetchedDocument  $fetch  fetches and checks the document
     * @param  bool  $refresh  fetch even when fresh, and never fall back to the cached copy
     */
    public function remember(string $key, int $staleIfErrorSeconds, Closure $fetch, bool $refresh = false): string
    {
        $now = $this->clock->now()->getTimestamp();
        $cached = $this->memo[$key] ?? null;

        if (! $refresh && $cached instanceof CachedDocument && $now < $cached->freshUntil) {
            return $cached->body;
        }

        // Another process may have fetched a newer copy into the store.
        $stored = CachedDocument::fromCache($this->store->get($key));

        if ($stored instanceof CachedDocument && (! $cached instanceof CachedDocument || $stored->fetchedAt >= $cached->fetchedAt)) {
            $cached = $this->memo[$key] = $stored;
        }

        if (! $refresh && $cached instanceof CachedDocument && $now < $cached->freshUntil) {
            return $cached->body;
        }

        try {
            $fetched = $fetch();
        } catch (ProviderUnavailable $unavailable) {
            if (! $refresh && $cached instanceof CachedDocument && $now < $cached->freshUntil + $staleIfErrorSeconds) {
                return $cached->body;
            }

            throw $unavailable;
        }

        $document = new CachedDocument($fetched->body, $now, $now + $fetched->lifetimeSeconds);
        $keepSeconds = $fetched->lifetimeSeconds + $staleIfErrorSeconds;

        if ($keepSeconds > 0) {
            $this->store->put($key, $document->toCache(), $keepSeconds);
        } else {
            $this->store->forget($key);
        }

        $this->memo[$key] = $document;

        return $document->body;
    }

    /**
     * Drops this process's copy, so the next read goes to the store, where
     * another process may have put a newer one.
     */
    public function forgetLocal(string $key): void
    {
        unset($this->memo[$key]);
    }

    /**
     * Takes a slot for $seconds unless another caller holds it. Atomic in
     * stores that support it, so it also rate-limits across processes.
     */
    public function claim(string $key, int $seconds): bool
    {
        return $this->store->add($key, $this->clock->now()->getTimestamp(), $seconds);
    }

    public function forget(string $key): void
    {
        unset($this->memo[$key]);
        $this->store->forget($key);
    }
}

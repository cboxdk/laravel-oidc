<?php

declare(strict_types=1);

namespace Cbox\Oidc\Cache;

use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Closure;
use Illuminate\Contracts\Cache\Repository;
use Psr\Clock\ClockInterface;

/**
 * Caches provider documents (discovery, key sets) in the application's cache
 * store, with a copy per process that is trusted for at most
 * {@see self::LOCAL_SECONDS} before the store is read again. A long-lived
 * worker (Octane, a queue worker) therefore sees {@see self::forget()} from
 * another process within seconds, not when its copy would go stale.
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
    /** How long this process trusts its copy before it reads the store again. */
    public const int LOCAL_SECONDS = 5;

    /** @var array<string, CachedDocument> */
    private array $memo = [];

    /** @var array<string, int> when the store was last read for each key */
    private array $checkedAt = [];

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
        $checkedRecently = $now - ($this->checkedAt[$key] ?? PHP_INT_MIN) < self::LOCAL_SECONDS;

        if (! $refresh && $checkedRecently && $cached instanceof CachedDocument && $now < $cached->freshUntil) {
            return $cached->body;
        }

        // Another process may have fetched a newer copy into the store, or
        // forgotten it: the store decides.
        $stored = CachedDocument::fromCache($this->store->get($key));
        $this->checkedAt[$key] = $now;

        if (! $stored instanceof CachedDocument) {
            unset($this->memo[$key]);
            $cached = null;
        } elseif (! $cached instanceof CachedDocument || $stored->fetchedAt >= $cached->fetchedAt) {
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
        $this->checkedAt[$key] = $now;

        return $document->body;
    }

    /**
     * Drops this process's copy, so the next read goes to the store, where
     * another process may have put a newer one.
     */
    public function forgetLocal(string $key): void
    {
        unset($this->memo[$key], $this->checkedAt[$key]);
    }

    /**
     * Takes a slot for $seconds unless another caller holds it. Atomic in
     * stores that support it, so it also rate-limits across processes.
     */
    public function claim(string $key, int $seconds): bool
    {
        return $this->store->add($key, $this->clock->now()->getTimestamp(), $seconds);
    }

    /**
     * Drops the document from the store and from this process. Other
     * processes stop using their copy within {@see self::LOCAL_SECONDS}.
     */
    public function forget(string $key): void
    {
        unset($this->memo[$key], $this->checkedAt[$key]);
        $this->store->forget($key);
    }
}

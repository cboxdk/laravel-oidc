<?php

declare(strict_types=1);

namespace Cbox\Oidc\Logout;

use Illuminate\Contracts\Cache\Repository;
use Psr\Clock\ClockInterface;

/**
 * Remembers the jti of every accepted logout token until the token could no
 * longer be valid, so the same token is accepted once (OpenID Connect
 * Back-Channel Logout 1.0, 2.6 step 7).
 *
 * It uses the cache store of oidc.cache.store with an atomic add, so every
 * server must share that store (redis, database, memcached); with the array
 * or file store each server remembers only its own.
 *
 * @internal
 */
final readonly class LogoutTokenReplayGuard
{
    /** Extra seconds a jti is remembered past the token's exp plus leeway. */
    private const int MARGIN_SECONDS = 60;

    public function __construct(
        private Repository $store,
        private ClockInterface $clock,
    ) {}

    /**
     * Records the jti; false when it was recorded already.
     */
    public function claim(string $connection, string $issuer, string $jti, int $expiresAt, int $leeway): bool
    {
        $ttl = max(1, $expiresAt + $leeway + self::MARGIN_SECONDS - $this->clock->now()->getTimestamp());

        return $this->store->add($this->key($connection, $issuer, $jti), true, $ttl);
    }

    /**
     * Forgets the jti of $token, so a delivery the application failed to
     * handle can be retried by the provider.
     */
    public function release(LogoutToken $token): void
    {
        $this->store->forget($this->key($token->connection, $token->issuer, $token->jti));
    }

    private function key(string $connection, string $issuer, string $jti): string
    {
        return 'oidc:logout-jti:'.hash('sha256', $connection."\n".$issuer."\n".$jti);
    }
}

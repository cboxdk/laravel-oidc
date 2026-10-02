<?php

declare(strict_types=1);

namespace Cbox\Oidc\Keys;

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Cache\FetchedDocument;
use Cbox\Oidc\Config\CacheConfig;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\KeySetInvalid;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Support\CacheControl;
use Cbox\Oidc\Support\ProviderDocument;

/**
 * Fetches, checks and caches each connection's key set (jwks_uri).
 *
 * A key set stays fresh for the provider's Cache-Control max-age, clamped to
 * [jwks_min_ttl_seconds, jwks_max_ttl_seconds], or jwks_default_ttl_seconds
 * without one. {@see self::refresh()} refetches it at once, at most once per
 * jwks_refetch_cooldown_seconds per connection, across processes.
 */
final readonly class KeySetRepository
{
    public function __construct(
        private HttpClient $http,
        private DocumentCache $documents,
        private CacheConfig $cache,
    ) {}

    /**
     * @throws KeySetInvalid
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     */
    public function for(ConnectionConfig $connection, ProviderMetadata $metadata): KeySet
    {
        return $this->load($connection, $metadata, refresh: false);
    }

    /**
     * The key set as the shared cache holds it now, bypassing this process's
     * copy; another process may have refetched it already.
     */
    public function reload(ConnectionConfig $connection, ProviderMetadata $metadata): KeySet
    {
        $this->documents->forgetLocal($this->key($connection, $metadata));

        return $this->for($connection, $metadata);
    }

    /**
     * Refetches the key set now, unless it was refetched within the cooldown;
     * then it returns null and fetches nothing. A token with a random kid
     * therefore costs at most one fetch per cooldown, not one per login.
     *
     * @throws KeySetInvalid
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     */
    public function refresh(ConnectionConfig $connection, ProviderMetadata $metadata): ?KeySet
    {
        if (! $this->documents->claim($this->key($connection, $metadata).':refetch', $this->cache->jwksRefetchCooldownSeconds)) {
            return null;
        }

        return $this->load($connection, $metadata, refresh: true);
    }

    /**
     * Drops the cached key set, so the next call fetches it again; for when a
     * provider withdraws a compromised key.
     */
    public function forget(ConnectionConfig $connection, ProviderMetadata $metadata): void
    {
        $this->documents->forget($this->key($connection, $metadata));
    }

    private function load(ConnectionConfig $connection, ProviderMetadata $metadata, bool $refresh): KeySet
    {
        $body = $this->documents->remember(
            $this->key($connection, $metadata),
            $this->cache->staleIfErrorSeconds,
            fn (): FetchedDocument => $this->fetch($connection, $metadata),
            $refresh,
        );

        return KeySet::fromDocument(ProviderDocument::fromBody($body, $metadata->jwksUri, 'key set'), $connection->name, $metadata->jwksUri);
    }

    private function fetch(ConnectionConfig $connection, ProviderMetadata $metadata): FetchedDocument
    {
        $response = $this->http->send(HttpRequest::get($metadata->jwksUri, ['Accept' => 'application/jwk-set+json, application/json']));

        // Checked before it is cached, so a wrong key set is never kept.
        KeySet::fromDocument(ProviderDocument::fromResponse($response, $metadata->jwksUri, 'key set'), $connection->name, $metadata->jwksUri);

        return new FetchedDocument($response->body, CacheControl::lifetime(
            $response->header('Cache-Control'),
            $this->cache->jwksDefaultTtlSeconds,
            $this->cache->jwksMinTtlSeconds,
            $this->cache->jwksMaxTtlSeconds,
        ));
    }

    private function key(ConnectionConfig $connection, ProviderMetadata $metadata): string
    {
        return 'oidc:jwks:'.hash('sha256', $connection->name."\n".$metadata->jwksUri);
    }
}

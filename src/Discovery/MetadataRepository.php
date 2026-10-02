<?php

declare(strict_types=1);

namespace Cbox\Oidc\Discovery;

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Cache\FetchedDocument;
use Cbox\Oidc\Config\CacheConfig;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Support\ProviderDocument;

/**
 * Fetches, checks and caches each connection's discovery document.
 *
 * A document is checked before it is cached, and again each time it is read,
 * so a change of the connection's configuration (its algorithms, say) takes
 * effect at once. It stays fresh for oidc.cache.discovery_ttl_seconds.
 */
final readonly class MetadataRepository
{
    public function __construct(
        private HttpClient $http,
        private DocumentCache $documents,
        private CacheConfig $cache,
    ) {}

    /**
     * @throws DiscoveryFailed when the document is wrong for the connection
     * @throws InvalidProviderResponse when it is not a JSON document at all
     * @throws ProviderUnavailable when it cannot be fetched and no usable copy is cached
     * @throws OutboundRequestBlocked when the SSRF guard refuses the discovery URL
     */
    public function for(ConnectionConfig $connection): ProviderMetadata
    {
        $body = $this->documents->remember(
            $this->key($connection),
            $this->cache->staleIfErrorSeconds,
            fn (): FetchedDocument => $this->fetch($connection),
        );

        return ProviderMetadata::fromDocument(ProviderDocument::fromBody($body, $connection->discoveryUrl, 'discovery document'), $connection);
    }

    /**
     * Drops the cached document, so the next call fetches it again.
     */
    public function forget(ConnectionConfig $connection): void
    {
        $this->documents->forget($this->key($connection));
    }

    private function fetch(ConnectionConfig $connection): FetchedDocument
    {
        $response = $this->http->send(HttpRequest::get($connection->discoveryUrl, ['Accept' => 'application/json']));
        $document = ProviderDocument::fromResponse($response, $connection->discoveryUrl, 'discovery document');

        // Checked before it is cached, so a wrong document is never kept.
        ProviderMetadata::fromDocument($document, $connection);

        return new FetchedDocument($response->body, $this->cache->discoveryTtlSeconds);
    }

    private function key(ConnectionConfig $connection): string
    {
        return 'oidc:discovery:'.hash('sha256', $connection->name."\n".$connection->discoveryUrl);
    }
}

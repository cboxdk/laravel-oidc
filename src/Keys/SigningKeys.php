<?php

declare(strict_types=1);

namespace Cbox\Oidc\Keys;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\SigningKeyNotFound;
use Cbox\Oidc\Exceptions\SigningKeyUnsuitable;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Jose\Component\Core\JWK;

/**
 * Finds the provider key that may verify a token, from the token header's
 * alg and kid, following key rotation.
 *
 * When the key is not in the cached key set, it first rereads the shared
 * cache (another process may have refetched it), then refetches the key set
 * once, rate-limited per connection. Inside the cooldown it fails without a
 * fetch.
 */
final readonly class SigningKeys
{
    public function __construct(
        private MetadataRepository $metadata,
        private KeySetRepository $keySets,
        private KeySelector $selector,
    ) {}

    /**
     * @throws SigningKeyNotFound
     * @throws SigningKeyUnsuitable
     */
    public function find(ConnectionConfig $connection, SigningAlgorithm $algorithm, ?string $kid): JWK
    {
        $metadata = $this->metadata->for($connection);

        try {
            return $this->selector->select($this->keySets->for($connection, $metadata), $algorithm, $kid, $connection->name);
        } catch (SigningKeyNotFound $missing) {
            if (! $missing->refetchable()) {
                throw $missing;
            }

            return $this->afterRotation($connection, $metadata, $algorithm, $kid, $missing);
        }
    }

    private function afterRotation(ConnectionConfig $connection, ProviderMetadata $metadata, SigningAlgorithm $algorithm, ?string $kid, SigningKeyNotFound $missing): JWK
    {
        try {
            return $this->selector->select($this->keySets->reload($connection, $metadata), $algorithm, $kid, $connection->name);
        } catch (SigningKeyNotFound $stillMissing) {
            if (! $stillMissing->refetchable()) {
                throw $stillMissing;
            }
        }

        $fresh = $this->keySets->refresh($connection, $metadata);

        if (! $fresh instanceof KeySet) {
            throw $missing->after('the key set was refetched within the cooldown, so it was not fetched again', retryLater: true);
        }

        try {
            return $this->selector->select($fresh, $algorithm, $kid, $connection->name);
        } catch (SigningKeyNotFound $afterRefetch) {
            throw $afterRefetch->after('also after refetching the key set');
        }
    }
}

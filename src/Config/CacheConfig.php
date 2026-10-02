<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;

/**
 * How long discovery documents and key sets are cached, and how long a stale
 * copy may stand in while the provider is unavailable.
 */
readonly class CacheConfig
{
    public function __construct(
        public ?string $store = null,
        public int $discoveryTtlSeconds = 86400,
        public int $jwksDefaultTtlSeconds = 3600,
        public int $jwksMinTtlSeconds = 300,
        public int $jwksMaxTtlSeconds = 86400,
        public int $jwksRefetchCooldownSeconds = 60,
        public int $staleIfErrorSeconds = 86400,
    ) {}

    public static function fromConfig(ConfigReader $config): self
    {
        $min = $config->int('jwks_min_ttl_seconds', 300, 0, 604800);
        $max = $config->int('jwks_max_ttl_seconds', 86400, 0, 604800);

        if ($min > $max) {
            throw InvalidConfiguration::at($config->key('jwks_min_ttl_seconds'), 'is larger than jwks_max_ttl_seconds', sprintf('Set %s to at most %s.', $config->key('jwks_min_ttl_seconds'), $config->key('jwks_max_ttl_seconds')));
        }

        return new self(
            $config->nullableString('store'),
            $config->int('discovery_ttl_seconds', 86400, 0, 604800),
            $config->int('jwks_default_ttl_seconds', 3600, $min, $max),
            $min,
            $max,
            $config->int('jwks_refetch_cooldown_seconds', 60, 1, 86400),
            $config->int('stale_if_error_seconds', 86400, 0, 604800),
        );
    }
}

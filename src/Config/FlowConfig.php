<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

/**
 * Limits for the authorization flow: how long a started login may wait for
 * its callback, and how many may wait at once in one session (one per open
 * login tab).
 */
readonly class FlowConfig
{
    public function __construct(
        public int $transactionTtlSeconds = 600,
        public int $maxPendingTransactions = 5,
    ) {}

    public static function fromConfig(ConfigReader $config): self
    {
        return new self(
            $config->int('transaction_ttl_seconds', 600, 30, 3600),
            $config->int('max_pending_transactions', 5, 1, 50),
        );
    }
}

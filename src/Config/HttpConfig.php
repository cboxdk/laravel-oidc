<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

/**
 * Limits for the outbound calls to the providers.
 *
 * $allowInsecureHttp is not read from oidc.http: it is on when a connection
 * sets allow_insecure_http, which only a local or testing environment
 * accepts, and lets the client send plain http to the URLs such a connection
 * has checked.
 */
readonly class HttpConfig
{
    public function __construct(
        public float $timeoutSeconds = 5.0,
        public float $connectTimeoutSeconds = 2.0,
        public int $maxResponseBytes = 262144,
        public bool $allowInsecureHttp = false,
    ) {}

    public function withInsecureHttp(): self
    {
        return new self($this->timeoutSeconds, $this->connectTimeoutSeconds, $this->maxResponseBytes, true);
    }

    public static function fromConfig(ConfigReader $config): self
    {
        return new self(
            $config->float('timeout_seconds', 5.0, 0.1, 60.0),
            $config->float('connect_timeout_seconds', 2.0, 0.1, 60.0),
            $config->int('max_response_bytes', 262144, 1024, 16777216),
        );
    }
}

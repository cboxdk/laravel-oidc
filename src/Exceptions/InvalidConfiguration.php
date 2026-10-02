<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * A value in config/oidc.php is missing or invalid. The message names the full
 * key, such as oidc.connections.main.issuer.
 */
class InvalidConfiguration extends OidcException
{
    public function __construct(
        private readonly string $key,
        string $problem,
        string $fix,
    ) {
        parent::__construct(ErrorCode::ConfigInvalid, sprintf('%s %s.', $key, $problem), $fix);
    }

    public static function at(string $key, string $problem, string $fix): self
    {
        return new self($key, $problem, $fix);
    }

    /** The full configuration key, such as oidc.connections.main.issuer. */
    public function key(): string
    {
        return $this->key;
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Cache;

/**
 * A document just fetched and checked, with how long it stays fresh.
 *
 * @internal
 */
final readonly class FetchedDocument
{
    public function __construct(
        public string $body,
        public int $lifetimeSeconds,
    ) {}
}

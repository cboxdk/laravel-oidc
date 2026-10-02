<?php

declare(strict_types=1);

namespace Cbox\Oidc\Cache;

/**
 * A provider document as the cache holds it: the raw body, already checked
 * when it was fetched, with the times (unix seconds, from the package clock)
 * it was fetched and stays fresh until.
 *
 * @internal
 */
final readonly class CachedDocument
{
    public function __construct(
        public string $body,
        public int $fetchedAt,
        public int $freshUntil,
    ) {}

    public static function fromCache(mixed $value): ?self
    {
        if (! is_array($value) || ! is_string($value['body'] ?? null) || ! is_int($value['fetched_at'] ?? null) || ! is_int($value['fresh_until'] ?? null)) {
            return null;
        }

        return new self($value['body'], $value['fetched_at'], $value['fresh_until']);
    }

    /**
     * @return array{body: string, fetched_at: int, fresh_until: int}
     */
    public function toCache(): array
    {
        return ['body' => $this->body, 'fetched_at' => $this->fetchedAt, 'fresh_until' => $this->freshUntil];
    }
}

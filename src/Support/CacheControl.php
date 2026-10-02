<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

/**
 * Reads how long a response may be cached from its Cache-Control header.
 *
 * @internal
 */
final class CacheControl
{
    /**
     * The max-age of $header clamped to [$min, $max]; $default when the
     * header has no max-age. no-store and no-cache count as max-age 0, so
     * they give $min: a provider that says "don't cache" still gets one
     * fetch per $min seconds, not one per login.
     */
    public static function lifetime(?string $header, int $default, int $min, int $max): int
    {
        $age = self::maxAge($header);

        return $age === null ? $default : max($min, min($max, $age));
    }

    private static function maxAge(?string $header): ?int
    {
        if ($header === null) {
            return null;
        }

        $age = null;

        foreach (explode(',', strtolower($header)) as $directive) {
            $directive = trim($directive);

            if ($directive === 'no-store' || $directive === 'no-cache') {
                return 0;
            }

            if (preg_match('/^max-age\s*=\s*"?(\d{1,10})"?$/', $directive, $match) === 1) {
                $age = (int) $match[1];
            }
        }

        return $age;
    }
}

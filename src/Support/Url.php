<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

/**
 * Renders URLs for exception messages without anything that could carry a
 * secret: no user info, query or fragment.
 *
 * @internal
 */
final class Url
{
    public static function origin(string $url): string
    {
        $parts = parse_url($url);

        if (! is_array($parts) || ! isset($parts['host'])) {
            return 'a URL that is not absolute';
        }

        return sprintf('%s://%s%s', $parts['scheme'] ?? '?', $parts['host'], isset($parts['port']) ? ':'.$parts['port'] : '');
    }

    public static function withoutQuery(string $url): string
    {
        $parts = parse_url($url);

        if (! is_array($parts) || ! isset($parts['host'])) {
            return 'a URL that is not absolute';
        }

        return self::origin($url).($parts['path'] ?? '');
    }
}

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

    /**
     * What tells two callback URLs apart: the host without case and the
     * decoded path without a trailing slash. Scheme and port are left out,
     * because a proxy that ends TLS can change both on the way to the
     * application.
     */
    public static function callbackTarget(string $url): string
    {
        $parts = parse_url($url);

        return self::target(is_array($parts) ? ($parts['host'] ?? '') : '', is_array($parts) ? ($parts['path'] ?? '') : '');
    }

    /**
     * Whether $host is one that only resolves on this machine or in local
     * development: localhost, a loopback address, or a name below .localhost
     * or .test (RFC 6761). Plain http is accepted for a browser redirect to
     * these alone (RFC 6749 3.1.2.1, RFC 8252 7.3).
     */
    public static function isLocalHost(string $host): bool
    {
        $host = strtolower($host);

        return in_array($host, ['localhost', '[::1]', '::1'], true)
            || preg_match('/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/D', $host) === 1
            || str_ends_with($host, '.localhost')
            || str_ends_with($host, '.test');
    }

    public static function target(string $host, string $path): string
    {
        $path = rtrim(rawurldecode($path), '/');

        return strtolower($host).($path === '' ? '/' : $path);
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

/**
 * Checks a URL taken from a provider's document before the package calls it
 * or sends a browser to it.
 *
 * @internal
 */
final class HttpsUrl
{
    /**
     * An absolute https URL with a host and without user info or fragment;
     * with $insecureHttp, an http URL too.
     */
    public static function valid(mixed $value, bool $insecureHttp = false): bool
    {
        if (! is_string($value) || $value === '' || strlen($value) > 2048 || preg_match('/[\x00-\x20\x7F]/', $value) === 1) {
            return false;
        }

        $parts = parse_url($value);

        return is_array($parts)
            && in_array(strtolower($parts['scheme'] ?? ''), $insecureHttp ? ['http', 'https'] : ['https'], true)
            && ($parts['host'] ?? '') !== ''
            && ! isset($parts['user'])
            && ! isset($parts['pass'])
            && ! isset($parts['fragment']);
    }
}

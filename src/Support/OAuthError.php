<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

/**
 * Reads the error code of an OAuth error response (RFC 6749 4.1.2.1, 5.2).
 *
 * Only the code is kept. error_description and error_uri are free text that
 * the other side (or an attacker who forges a callback) controls, so they
 * never reach an exception message, a log or a page.
 *
 * @internal
 */
final class OAuthError
{
    /** Stands in for an error value that is not a valid OAuth error code. */
    public const string UNRECOGNIZED = 'unrecognized_error';

    /**
     * The error code, or {@see self::UNRECOGNIZED} when $value is not one.
     *
     * RFC 6749 allows most printable ASCII, markup included. Every registered
     * code is letters and underscores, so only 1 to 64 letters, digits, dots,
     * dashes and underscores are kept: a code can then go into a log, a
     * message or a page as it is.
     */
    public static function code(mixed $value): string
    {
        return is_string($value) && preg_match('/^[A-Za-z0-9._-]{1,64}$/D', $value) === 1
            ? $value
            : self::UNRECOGNIZED;
    }
}

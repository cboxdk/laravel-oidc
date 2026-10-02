<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Support\Base64Url;

/**
 * PKCE with S256 (RFC 7636). The verifier stays in the transaction; only its
 * SHA-256 travels in the authorization URL, so a stolen code cannot be
 * redeemed without it. S256 is always used, also by confidential clients.
 *
 * @internal Not part of the public API; it may change in any release.
 */
final class Pkce
{
    public const string METHOD = 'S256';

    /** A fresh verifier: 32 random bytes, 43 characters (the RFC's minimum length). */
    public static function verifier(): string
    {
        return Base64Url::random(32);
    }

    public static function challenge(string $verifier): string
    {
        return Base64Url::encode(hash('sha256', $verifier, true));
    }
}

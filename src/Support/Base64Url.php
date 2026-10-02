<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

/**
 * Unpadded base64url (RFC 4648 5), as PKCE, state and nonce values use it.
 *
 * @internal
 */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /**
     * Decodes unpadded base64url, strictly: only the base64url alphabet, no
     * padding, and only the one canonical encoding of the bytes (the unused
     * low bits of the last character must be zero). Null for anything else.
     */
    public static function decode(string $encoded): ?string
    {
        if (preg_match('/^[A-Za-z0-9_-]*$/D', $encoded) !== 1 || strlen($encoded) % 4 === 1) {
            return null;
        }

        $bytes = base64_decode(strtr($encoded, '-_', '+/'), true);

        return is_string($bytes) && self::encode($bytes) === $encoded ? $bytes : null;
    }

    /**
     * A fresh random value of $bytes bytes from the system CSPRNG, encoded.
     * 32 bytes give 43 characters and 256 bits of entropy.
     *
     * @param  int<1, max>  $bytes
     */
    public static function random(int $bytes = 32): string
    {
        return self::encode(random_bytes($bytes));
    }
}

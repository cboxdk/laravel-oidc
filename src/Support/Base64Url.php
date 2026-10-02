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

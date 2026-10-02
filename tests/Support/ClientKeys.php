<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use LogicException;

/**
 * Client private keys in PEM form, as an application keeps them for
 * private_key_jwt. Each is made once per test run.
 */
final class ClientKeys
{
    /** @var array<string, string> */
    private static array $pems = [];

    public static function rsa(int $bits = 2048): string
    {
        return self::make("rsa$bits", ['private_key_type' => OPENSSL_KEYTYPE_RSA, 'private_key_bits' => $bits]);
    }

    public static function ec(string $curve = 'prime256v1'): string
    {
        return self::make("ec-$curve", ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => $curve]);
    }

    public static function ed25519(): string
    {
        return self::make('ed25519', ['private_key_type' => OPENSSL_KEYTYPE_ED25519]);
    }

    public static function encryptedRsa(string $passphrase): string
    {
        $key = openssl_pkey_get_private(self::rsa());

        if ($key === false || ! openssl_pkey_export($key, $pem, $passphrase)) {
            throw new LogicException('Could not encrypt the test key.');
        }

        return $pem;
    }

    public static function publicRsa(): string
    {
        $key = openssl_pkey_get_private(self::rsa());
        $details = $key === false ? false : openssl_pkey_get_details($key);

        if ($details === false || ! is_string($details['key'] ?? null)) {
            throw new LogicException('Could not read the test key.');
        }

        return $details['key'];
    }

    /** The public half as a JWK, as the provider registers it. */
    public static function publicJwk(string $pem): JWK
    {
        return JWKFactory::createFromKey($pem, '')->toPublic();
    }

    /**
     * @param  array<string, mixed>  $options
     */
    private static function make(string $name, array $options): string
    {
        if (isset(self::$pems[$name])) {
            return self::$pems[$name];
        }

        $key = openssl_pkey_new($options);

        if ($key === false || ! openssl_pkey_export($key, $pem)) {
            throw new LogicException(sprintf('Could not make the test key %s.', $name));
        }

        return self::$pems[$name] = $pem;
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * No key of the provider's key set can verify the token: the key id is
 * unknown, or without a key id no single key fits the algorithm.
 *
 * An unknown key id usually means the provider rotated its keys; the package
 * then refetches the key set once, rate-limited per connection.
 */
class SigningKeyNotFound extends OidcException
{
    private bool $refetchable = false;

    public static function unknownKid(string $connection, string $kid): self
    {
        $exception = new self(
            ErrorCode::SigningKeyNotFound,
            sprintf('The key set of connection "%s" has no key with kid "%s".', $connection, self::shorten($kid)),
            'If the provider just rotated its keys, the next attempt refetches them. If it persists, the token was not issued by this connection\'s provider.',
        );
        $exception->refetchable = true;

        return $exception;
    }

    public static function noSuitableKey(string $connection, string $algorithm): self
    {
        $exception = new self(
            ErrorCode::SigningKeyNotFound,
            sprintf('The token names no kid, and the key set of connection "%s" has no key for %s.', $connection, $algorithm),
            'Check that the provider signs with an algorithm whose key it publishes at jwks_uri.',
        );
        $exception->refetchable = true;

        return $exception;
    }

    public static function ambiguous(string $connection, string $algorithm, int $count): self
    {
        return new self(
            ErrorCode::SigningKeyNotFound,
            sprintf('The token names no kid, and the key set of connection "%s" has %d keys for %s, so the key is ambiguous.', $connection, $count, $algorithm),
            'Configure the provider to put a kid in the token header; with several keys the package never tries them one by one.',
        );
    }

    /**
     * The same failure after the key set was refetched, or while a refetch is
     * held back by the cooldown.
     */
    public function after(string $what): self
    {
        return new self(
            $this->errorCode(),
            sprintf('%s (%s).', rtrim($this->problem(), '.'), $what),
            $this->fix(),
            $this,
        );
    }

    /** Whether refetching the key set could help (the provider may have rotated). */
    public function refetchable(): bool
    {
        return $this->refetchable;
    }

    private static function shorten(string $value): string
    {
        return strlen($value) > 100 ? substr($value, 0, 100).'...' : $value;
    }
}

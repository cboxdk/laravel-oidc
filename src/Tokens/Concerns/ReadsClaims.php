<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens\Concerns;

use DateTimeImmutable;

/**
 * Read access to a set of claims as the provider sent them, for
 * VerifiedClaims, UserInfo and LogoutToken. The using class has a public
 * array $claims of type array<string, mixed>.
 *
 * The typed readers (string(), int(), bool(), stringList(), time()) return
 * null for a claim that is missing or has another JSON type, so code on
 * PHPStan's strictest level needs no narrowing of its own. claim() is the
 * untyped escape hatch, for claims of other shapes.
 */
trait ReadsClaims
{
    /** Whether the claim $name was sent, even with a null value. */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    /** The claim $name as sent, of any JSON type, or $default when there is none. */
    public function claim(string $name, mixed $default = null): mixed
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }

    /** The claim $name when it is a string; null otherwise. */
    public function string(string $name): ?string
    {
        $value = $this->claims[$name] ?? null;

        return is_string($value) ? $value : null;
    }

    /** The claim $name when it is a JSON integer; null otherwise (a numeric string included). */
    public function int(string $name): ?int
    {
        $value = $this->claims[$name] ?? null;

        return is_int($value) ? $value : null;
    }

    /** The claim $name when it is JSON true or false; null otherwise (the strings "true" and "false" included). */
    public function bool(string $name): ?bool
    {
        $value = $this->claims[$name] ?? null;

        return is_bool($value) ? $value : null;
    }

    /**
     * The claim $name when it is a list of strings, such as groups or amr;
     * null otherwise, also when one item is not a string.
     *
     * @return list<string>|null
     */
    public function stringList(string $name): ?array
    {
        $value = $this->claims[$name] ?? null;

        if (! is_array($value) || ! array_is_list($value)) {
            return null;
        }

        $strings = array_values(array_filter($value, is_string(...)));

        return count($strings) === count($value) ? $strings : null;
    }

    /**
     * The claim $name when it is a time in seconds since the epoch (a JSON
     * integer, as exp, iat and auth_time are), in UTC; null otherwise.
     */
    public function time(string $name): ?DateTimeImmutable
    {
        $value = $this->int($name);

        return $value === null ? null : new DateTimeImmutable('@'.$value);
    }

    /**
     * Every claim, as sent.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}

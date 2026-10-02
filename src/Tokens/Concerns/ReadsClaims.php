<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens\Concerns;

/**
 * Read access to a set of claims as the provider sent them, for
 * VerifiedClaims and UserInfo. The using class has a public array $claims
 * of type array<string, mixed>.
 */
trait ReadsClaims
{
    /** Whether the claim $name was sent, even with a null value. */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    /** The claim $name as sent, or $default when there is none. */
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

    /**
     * The email claim. Use it to contact the person, not to identify them:
     * check {@see self::emailVerified()} before you trust it, and match
     * accounts on issuer and subject.
     */
    public function email(): ?string
    {
        return $this->string('email');
    }

    /** Whether the provider says it verified the email address: true only for the JSON value true. */
    public function emailVerified(): bool
    {
        return ($this->claims['email_verified'] ?? null) === true;
    }

    /** The name claim, the person's full name for display. */
    public function name(): ?string
    {
        return $this->string('name');
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

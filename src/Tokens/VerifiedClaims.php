<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use DateTimeImmutable;

/**
 * The claims of an ID token that passed every check: who the person is
 * (issuer and subject), how and when they signed in, their tenant and their
 * groups, and every other claim through {@see self::claim()}.
 *
 * Identify a person by issuer and subject together, never by email: the
 * subject is unique and stable per issuer (OpenID Connect Core 2), an email
 * address is neither.
 */
final readonly class VerifiedClaims
{
    /**
     * @param  non-empty-list<string>  $audience
     * @param  list<string>|null  $authenticationMethods  amr, each method once
     * @param  list<string>|null  $groups  null when unknown: the connection reads no groups from the ID token, or the provider left them out (Entra's group overage)
     * @param  array<string, mixed>  $claims  every claim of the token, as sent
     */
    public function __construct(
        public string $connection,
        public string $issuer,
        public string $subject,
        public array $audience,
        public ?string $authorizedParty,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?DateTimeImmutable $authTime,
        public ?array $authenticationMethods,
        public ?string $authenticationContext,
        public ?string $sessionId,
        public ?string $tenant,
        public ?array $groups,
        public bool $groupsOverage,
        public array $claims,
    ) {}

    /** Whether the token has the claim $name, even with a null value. */
    public function has(string $name): bool
    {
        return array_key_exists($name, $this->claims);
    }

    /** The claim $name as sent, or $default when the token has none. */
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
     * Every claim of the token, as sent.
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->claims;
    }
}

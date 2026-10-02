<?php

declare(strict_types=1);

namespace Cbox\Oidc\Logout;

use Cbox\Oidc\Tokens\VerifiedClaims;
use DateTimeImmutable;

/**
 * A logout token that passed every check of {@see LogoutTokenVerifier}: the
 * provider says the person's session there ended, and asks you to end yours
 * (OpenID Connect Back-Channel Logout 1.0).
 *
 * - With a $sessionId (sid), end the sessions that signed in with the ID
 *   token of that sid ({@see VerifiedClaims::$sessionId}).
 * - With only a $subject, end every session of that person at this issuer.
 *
 * {@see self::matches()} tells whether the claims of one of your sessions
 * are meant.
 */
final readonly class LogoutToken
{
    /**
     * @param  array<string, mixed>  $claims  every claim of the token, as sent
     */
    public function __construct(
        public string $connection,
        public string $issuer,
        public ?string $subject,
        public ?string $sessionId,
        public string $jti,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public array $claims,
    ) {}

    /** Whether the token ends one provider session (sid) rather than every session of the person. */
    public function endsOneSession(): bool
    {
        return $this->sessionId !== null;
    }

    /**
     * Whether the session that signed in with $claims is one to end: the
     * same connection and issuer, the same sid when the token has one, and
     * the same subject when the token has one.
     */
    public function matches(VerifiedClaims $claims): bool
    {
        if ($claims->connection !== $this->connection || $claims->issuer !== $this->issuer) {
            return false;
        }

        if ($this->sessionId !== null && ($claims->sessionId === null || ! hash_equals($this->sessionId, $claims->sessionId))) {
            return false;
        }

        return $this->subject === null || hash_equals($this->subject, $claims->subject);
    }

    /** The claim $name as sent, or $default when there is none. */
    public function claim(string $name, mixed $default = null): mixed
    {
        return array_key_exists($name, $this->claims) ? $this->claims[$name] : $default;
    }
}

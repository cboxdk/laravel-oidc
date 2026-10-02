<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Tokens\Concerns\ReadsClaims;
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
    use ReadsClaims;

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

    /**
     * A copy with the groups replaced, such as the groups userinfo returned
     * for a connection whose groups.source is userinfo.
     *
     * @param  list<string>|null  $groups
     */
    public function withGroups(?array $groups, bool $overage = false): self
    {
        return new self(
            $this->connection, $this->issuer, $this->subject, $this->audience, $this->authorizedParty,
            $this->issuedAt, $this->expiresAt, $this->authTime, $this->authenticationMethods,
            $this->authenticationContext, $this->sessionId, $this->tenant, $groups, $overage, $this->claims,
        );
    }
}

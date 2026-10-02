<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use DateTimeImmutable;
use SensitiveParameter;

/**
 * The tokens of a successful token response (RFC 6749 5.1, OpenID Connect
 * Core 3.1.3.3). Every token is a secret: a dump shows whether each is
 * present, never its value.
 */
final readonly class TokenSet
{
    /**
     * @param  list<string>|null  $scopes  the granted scopes, when the provider names them
     */
    public function __construct(
        #[SensitiveParameter] public string $accessToken,
        public string $tokenType,
        #[SensitiveParameter] public ?string $idToken,
        #[SensitiveParameter] public ?string $refreshToken,
        public ?int $expiresIn,
        public ?DateTimeImmutable $expiresAt,
        public ?array $scopes,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'accessToken' => '[redacted]',
            'tokenType' => $this->tokenType,
            'idToken' => $this->idToken === null ? null : '[redacted]',
            'refreshToken' => $this->refreshToken === null ? null : '[redacted]',
            'expiresIn' => $this->expiresIn,
            'expiresAt' => $this->expiresAt,
            'scopes' => $this->scopes,
        ];
    }
}

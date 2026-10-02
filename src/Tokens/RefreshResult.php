<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use SensitiveParameter;

/**
 * A refresh the provider accepted.
 *
 * - $tokens: the new token response; use $tokens->accessToken from now on.
 * - $refreshToken: the refresh token to keep. Providers that rotate refresh
 *   tokens return a new one, which replaces the old one ({@see self::$rotated});
 *   the others return none, and the old one stays valid.
 * - $claims: the claims of the new ID token, verified and checked to belong
 *   to the same login; the original claims when the provider returned no ID
 *   token ({@see self::$idTokenRenewed}).
 */
final readonly class RefreshResult
{
    public function __construct(
        public TokenSet $tokens,
        #[SensitiveParameter] public string $refreshToken,
        public bool $rotated,
        public VerifiedClaims $claims,
        public bool $idTokenRenewed,
    ) {}

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'tokens' => $this->tokens,
            'refreshToken' => '[redacted]',
            'rotated' => $this->rotated,
            'claims' => $this->claims,
            'idTokenRenewed' => $this->idTokenRenewed,
        ];
    }
}

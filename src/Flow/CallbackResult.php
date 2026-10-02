<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Tokens\TokenSet;
use Cbox\Oidc\Tokens\VerifiedClaims;

/**
 * A login that passed every check: the verified claims of its ID token, the
 * tokens the provider returned for its code, and the login itself.
 *
 * Sign the person in from $claims: identify them by $claims->issuer and
 * $claims->subject together. $transaction is the login the callback matched;
 * $responseIssuer is the callback's iss parameter (RFC 9207), when it had one.
 */
final readonly class CallbackResult
{
    public function __construct(
        public string $connection,
        public VerifiedClaims $claims,
        public TokenSet $tokens,
        public AuthorizationTransaction $transaction,
        public ?string $responseIssuer,
    ) {}
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Tokens\TokenSet;

/**
 * A callback that passed every check before the token request, and the
 * tokens the provider returned for its code.
 *
 * $transaction carries the nonce and max_age the ID token is checked
 * against; $responseIssuer is the callback's iss parameter (RFC 9207), when
 * it had one.
 */
final readonly class CallbackResult
{
    public function __construct(
        public string $connection,
        public TokenSet $tokens,
        public AuthorizationTransaction $transaction,
        public ?string $responseIssuer,
    ) {}
}

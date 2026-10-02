<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * The key the token names exists in the provider's key set, but may not
 * verify a token with the token's algorithm: its type, curve or size does not
 * fit, it is marked for another use or algorithm, or it is malformed. The key
 * set is not refetched, since the key itself was found.
 */
class SigningKeyUnsuitable extends OidcException
{
    /**
     * @param  non-empty-list<string>  $reasons
     */
    public static function because(string $connection, string $kid, string $algorithm, array $reasons): self
    {
        return new self(
            ErrorCode::SigningKeyUnsuitable,
            sprintf('The key "%s" of connection "%s" may not verify a %s token: %s.', strlen($kid) > 100 ? substr($kid, 0, 100).'...' : $kid, $connection, $algorithm, implode('; ', $reasons)),
            'Nothing to change on this side if the token was forged. Otherwise the provider signs with a key unfit for the algorithm; check its key configuration.',
        );
    }
}

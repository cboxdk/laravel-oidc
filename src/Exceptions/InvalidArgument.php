<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * A value passed to a package method cannot be what the method expects, such
 * as an empty refresh token or a scope with a space in it. A programming
 * error, or a stored value that was damaged: fix the call.
 */
class InvalidArgument extends OidcException
{
    public static function because(string $argument, string $problem, string $fix): self
    {
        return new self(ErrorCode::ArgumentInvalid, sprintf('The argument %s %s.', $argument, $problem), $fix);
    }

    /**
     * Checks a token handed back to the package: 1 to $max printable ASCII
     * characters, as providers issue them.
     *
     * @throws self
     */
    public static function assertToken(string $argument, string $token, int $max = 16384): void
    {
        if ($token === '' || strlen($token) > $max || preg_match('/^[\x20-\x7E]+$/D', $token) !== 1) {
            throw self::because($argument, sprintf('is not 1 to %d printable ASCII characters', $max), 'Pass the token exactly as the provider issued it; check that it was stored without truncation or extra whitespace.');
        }
    }

    /**
     * Checks scope tokens (RFC 6749 3.3).
     *
     * @param  list<string>  $scopes
     *
     * @throws self
     */
    public static function assertScopes(string $argument, array $scopes): void
    {
        foreach ($scopes as $scope) {
            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]{1,255}$/D', $scope) !== 1) {
                throw self::because($argument, 'has a value that is not a valid scope', 'Use printable ASCII without spaces, quotes or backslashes for each scope (RFC 6749 3.3).');
            }
        }
    }
}

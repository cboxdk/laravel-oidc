<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Flow\AuthorizationOptions;

/**
 * The {@see AuthorizationOptions} passed when starting a login are invalid.
 * A programming error: fix the call.
 */
class InvalidAuthorizationOptions extends OidcException
{
    public static function because(string $problem, string $fix): self
    {
        return new self(ErrorCode::AuthorizationOptionsInvalid, sprintf('The authorization options are invalid: %s.', $problem), $fix);
    }
}

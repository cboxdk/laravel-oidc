<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * A value passed in LogoutOptions is invalid. The message names the option.
 */
class InvalidLogoutOptions extends OidcException
{
    public static function option(string $option, string $problem, string $fix): self
    {
        return new self(ErrorCode::LogoutOptionsInvalid, sprintf('The logout option %s %s.', $option, $problem), $fix);
    }
}

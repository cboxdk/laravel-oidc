<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * The provider answered the login with an OAuth error instead of a code:
 * the person declined, or a silent login (prompt=none) needs interaction.
 *
 * {@see self::error()} gives the error code, so a silent login can fall back
 * to an interactive one on login_required. error_description is never read:
 * it is free text anyone can put in a callback URL.
 */
class AuthorizationDenied extends OidcException
{
    /** The errors a prompt=none login returns when the person must interact (OpenID Connect Core 3.1.2.6). */
    public const array INTERACTION_REQUIRED = ['account_selection_required', 'consent_required', 'interaction_required', 'login_required'];

    private string $error = '';

    public static function byProvider(string $connection, string $error): self
    {
        $exception = new self(
            ErrorCode::AuthorizationDenied,
            sprintf('The provider of connection "%s" answered the login with the error %s.', $connection, $error),
            match (true) {
                $error === 'access_denied' => 'The person declined, or the provider does not let them use this application. Let them try again, or check the assignment of users to the client at the provider.',
                in_array($error, self::INTERACTION_REQUIRED, true) => 'A silent login (prompt=none) needs the person to interact. Start a normal login.',
                default => 'Check the provider\'s log for this client; the error code names the cause.',
            },
        );
        $exception->error = $error;

        return $exception;
    }

    /** The OAuth error code, such as access_denied or login_required. */
    public function error(): string
    {
        return $this->error;
    }

    /** Whether a silent login failed only because the person must interact. */
    public function interactionRequired(): bool
    {
        return in_array($this->error, self::INTERACTION_REQUIRED, true);
    }
}

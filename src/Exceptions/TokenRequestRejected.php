<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;

/**
 * The token endpoint refused a request with an OAuth error (RFC 6749 5.2),
 * such as invalid_grant for a code that expired or was used, or
 * invalid_client for wrong client credentials.
 *
 * {@see self::error()} gives the error code. error_description is never
 * read into the message.
 */
class TokenRequestRejected extends OidcException
{
    private string $error = '';

    private string $grant = 'authorization_code';

    /**
     * @param  string  $grant  the grant_type of the refused request
     */
    public static function byProvider(string $connection, string $url, int $status, string $error, string $grant = 'authorization_code'): self
    {
        $exception = new self(
            ErrorCode::TokenRequestRejected,
            sprintf('The token endpoint %s of connection "%s" refused the request with HTTP %d and the error %s.', Url::withoutQuery($url), $connection, $status, $error),
            match (true) {
                $error === 'invalid_grant' && $grant === 'refresh_token' => 'The refresh token expired, was revoked, or was used already by a provider that rotates refresh tokens. Drop it and sign the person in again.',
                $error === 'invalid_client' => sprintf('Check client_id, client_secret (or the client_assertion key) and client_auth of oidc.connections.%s against the client registered at the provider.', $connection),
                $error === 'invalid_grant' => 'The code expired, was already used, or was issued for another redirect_uri or PKCE verifier. Start the login again; if every login fails this way, check that redirect_uri is registered exactly as configured.',
                $error === 'unauthorized_client' => 'The client may not use this grant type. Enable the authorization code grant (and refresh tokens, if used) for the client at the provider.',
                default => 'Check the provider\'s log for this client; the error code names the cause.',
            },
        );
        $exception->error = $error;
        $exception->grant = $grant;

        return $exception;
    }

    /** The OAuth error code, such as invalid_grant or invalid_client. */
    public function error(): string
    {
        return $this->error;
    }

    /** The grant_type of the refused request: authorization_code or refresh_token. */
    public function grant(): string
    {
        return $this->grant;
    }

    /**
     * Whether the provider refused a refresh token for good (invalid_grant):
     * the session it kept alive is over, and the person must sign in again.
     */
    public function refreshTokenInvalid(): bool
    {
        return $this->grant === 'refresh_token' && $this->error === 'invalid_grant';
    }
}

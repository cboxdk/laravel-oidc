<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;

/**
 * The revocation endpoint refused the request with an OAuth error (RFC 7009
 * 2.2.1), such as invalid_client or unsupported_token_type.
 *
 * An unknown or already invalid token is not an error: the provider answers
 * 200 for it, and so does the package.
 */
class RevocationRejected extends OidcException
{
    private string $error = '';

    public static function byProvider(string $connection, string $url, int $status, string $error): self
    {
        $exception = new self(
            ErrorCode::RevocationRejected,
            sprintf('The revocation endpoint %s of connection "%s" refused the request with HTTP %d and the error %s.', Url::withoutQuery($url), $connection, $status, $error),
            match ($error) {
                'invalid_client' => sprintf('Check client_id, client_secret (or the client_assertion key) and client_auth of oidc.connections.%s against the client registered at the provider.', $connection),
                'unsupported_token_type' => 'The provider does not revoke this kind of token. Many providers revoke refresh tokens only; revoke the refresh token instead.',
                default => 'Check the provider\'s log for this client; the error code names the cause.',
            },
        );
        $exception->error = $error;

        return $exception;
    }

    /** The OAuth error code, such as invalid_client or unsupported_token_type. */
    public function error(): string
    {
        return $this->error;
    }
}

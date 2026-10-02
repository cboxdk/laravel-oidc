<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;

/**
 * The userinfo endpoint did not give the person's claims: it refused the
 * access token (401 or 403, RFC 6750 3.1), or the claims it gave belong to
 * someone else than the ID token's subject (OpenID Connect Core 5.3.4).
 *
 * {@see self::error()} gives the Bearer error code from WWW-Authenticate,
 * such as invalid_token or insufficient_scope, when the provider sent one.
 */
class UserInfoRejected extends OidcException
{
    private ?string $error = null;

    public static function byProvider(string $connection, string $url, int $status, ?string $error): self
    {
        $exception = new self(
            ErrorCode::UserInfoRejected,
            sprintf('The userinfo endpoint %s of connection "%s" refused the access token with HTTP %d%s.', Url::withoutQuery($url), $connection, $status, $error === null ? '' : ' and the error '.$error),
            match ($error) {
                'insufficient_scope' => sprintf('Request the scopes the claims need (openid at least) in oidc.connections.%s.scopes.', $connection),
                default => 'The access token expired or was revoked. Refresh it (TokenRefresher) or sign the person in again, then call userinfo with the new access token.',
            },
        );
        $exception->error = $error;

        return $exception;
    }

    public static function subjectMismatch(string $connection): self
    {
        return new self(
            ErrorCode::UserInfoSubjectMismatch,
            sprintf('The userinfo response of connection "%s" names another sub than the ID token.', $connection),
            'Do not use these claims: they belong to someone else (OpenID Connect Core 5.3.4). The access token was likely swapped; sign the person in again.',
        );
    }

    /** The Bearer error code from WWW-Authenticate, such as invalid_token; null when the provider sent none. */
    public function error(): ?string
    {
        return $this->error;
    }
}

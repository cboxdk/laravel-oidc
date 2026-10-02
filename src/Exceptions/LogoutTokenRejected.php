<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Tokens\TokenKind;

/**
 * A logout token verified as a token of the provider, but breaks a rule only
 * logout tokens have (OpenID Connect Back-Channel Logout 1.0, 2.6), or was
 * accepted once already.
 *
 * The rules logout tokens share with ID tokens (form, signature, iss, aud,
 * exp, iat) fail with {@see TokenRejected}, the parent of this class, so
 * catching TokenRejected catches every refused logout token.
 */
class LogoutTokenRejected extends TokenRejected
{
    public static function invalid(string $connection, string $claim, string $problem): self
    {
        return static::make(
            ErrorCode::LogoutTokenInvalid,
            sprintf('The %s of connection "%s" %s.', TokenKind::LogoutToken->label(), $connection, $problem),
            'Answer the provider with 400 and end no session. If the provider sends every logout token this way, it does not follow OpenID Connect Back-Channel Logout 1.0; check its configuration for this client.',
            $claim,
        );
    }

    public static function replayed(string $connection): self
    {
        return static::make(
            ErrorCode::LogoutTokenReplayed,
            sprintf('A %s of connection "%s" with this jti was accepted already.', TokenKind::LogoutToken->label(), $connection),
            'Nothing to fix when it is a replay. If the provider retries deliveries that succeeded, make sure the application answers 200 promptly; the jti is remembered in the cache store of oidc.cache.store, which every server must share.',
            'jti',
        );
    }
}

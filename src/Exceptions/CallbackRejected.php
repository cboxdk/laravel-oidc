<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * The browser came back to the callback with a request the package refuses
 * before it asks the provider for tokens: no login of this session matches
 * its state, the login is too old, the iss parameter is wrong, or the code is
 * missing or malformed.
 *
 * Show the person a "start again" page; never retry the callback itself.
 */
class CallbackRejected extends OidcException
{
    public static function stateMismatch(string $connection, string $reason): self
    {
        return new self(
            ErrorCode::StateMismatch,
            sprintf('The callback of connection "%s" was refused: %s.', $connection, $reason),
            'Start the login again. If every login fails this way, the session does not survive the trip to the provider: keep the session cookie SameSite=lax (not strict), on the domain of the callback, and make sure nothing regenerates the session between the redirect and the callback.',
        );
    }

    public static function expired(string $connection, int $ageSeconds, int $ttlSeconds): self
    {
        return new self(
            ErrorCode::TransactionExpired,
            sprintf('The login of connection "%s" was started %d seconds ago, longer than the %d seconds a login may take.', $connection, $ageSeconds, $ttlSeconds),
            'Start the login again. Raise oidc.flow.transaction_ttl_seconds if people legitimately need longer at the provider.',
        );
    }

    public static function issuerMismatch(string $connection, string $expected, ?string $actual): self
    {
        return new self(
            ErrorCode::CallbackIssuerMismatch,
            $actual === null
                ? sprintf('The callback of connection "%s" has no iss parameter, although the provider announces it (authorization_response_iss_parameter_supported, RFC 9207).', $connection)
                : sprintf('The callback of connection "%s" names the issuer "%s", but the connection pins "%s" (RFC 9207). The response may come from another provider (a mix-up attack).', $connection, self::shorten($actual), $expected),
            'Start the login again. If it persists, check that each connection has its own redirect_uri, and that the provider\'s callback goes to the route of this connection.',
        );
    }

    public static function invalid(string $connection, string $problem): self
    {
        return new self(
            ErrorCode::CallbackInvalid,
            sprintf('The callback of connection "%s" %s.', $connection, $problem),
            'Start the login again. If it persists, check that the provider redirects to redirect_uri with response_type=code and the default query response mode.',
        );
    }

    private static function shorten(string $value): string
    {
        $value = (string) preg_replace('/[^\x20-\x7E]/', '?', $value);

        return strlen($value) > 200 ? substr($value, 0, 200).'...' : $value;
    }
}

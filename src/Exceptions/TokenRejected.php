<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Tokens\TokenKind;
use Throwable;

/**
 * A token from the provider failed verification: its form, signature or a
 * claim. {@see self::errorCode()} names the rule it broke and
 * {@see self::claim()} the claim or header member, when one is to blame.
 *
 * Never sign anyone in after this exception. Show the person a "sign-in
 * failed" page and log the exception: the message names the rule, never a
 * token or a secret.
 */
class TokenRejected extends OidcException
{
    private ?string $claim = null;

    final public function __construct(ErrorCode $errorCode, string $problem, string $fix, ?Throwable $previous = null)
    {
        parent::__construct($errorCode, $problem, $fix, $previous);
    }

    public static function malformed(TokenKind $kind, string $connection, string $problem, ?string $claim = null): self
    {
        return static::make(
            ErrorCode::TokenMalformed,
            sprintf('The %s of connection "%s" %s.', $kind->label(), $connection, $problem),
            'The package reads only compact, signed JWTs. If the provider encrypts tokens for this client (JWE), turn that off; otherwise the token was damaged on the way, or is not from the provider.',
            $claim,
        );
    }

    public static function typeInvalid(TokenKind $kind, string $connection, string $type): self
    {
        return static::make(
            ErrorCode::TokenTypeInvalid,
            sprintf('The %s of connection "%s" has the typ "%s", the type of another kind of token.', $kind->label(), $connection, self::shorten($type)),
            match ($kind) {
                TokenKind::IdToken => 'Only an ID token is accepted here. A logout or access token offered in its place is refused on purpose (RFC 8725 3.11).',
                TokenKind::LogoutToken => 'Only a logout token (typ logout+jwt, JWT or none) is accepted here. Another kind of token offered in its place is refused on purpose (RFC 8725 3.11).',
            },
            'typ',
        );
    }

    /**
     * @param  list<string>  $allowed
     */
    public static function algorithmNotAllowed(TokenKind $kind, string $connection, ?string $algorithm, array $allowed): self
    {
        $never = $algorithm !== null && (strtolower($algorithm) === 'none' || str_starts_with(strtoupper($algorithm), 'HS'));

        return static::make(
            ErrorCode::TokenAlgorithmNotAllowed,
            match (true) {
                $algorithm === null => sprintf('The %s of connection "%s" names no alg.', $kind->label(), $connection),
                $never => sprintf('The %s of connection "%s" uses alg %s, which is never accepted: an unsigned token, or one signed with a shared secret, proves nothing about the provider.', $kind->label(), $connection, self::shorten($algorithm)),
                default => sprintf('The %s of connection "%s" uses alg %s, which is not one of the algorithms accepted for it (%s).', $kind->label(), $connection, self::shorten($algorithm), implode(', ', $allowed)),
            },
            $never
                ? 'Nothing to configure: the token is forged, or the provider is set up to sign with a shared secret. Configure the client at the provider to sign ID tokens with RS256 or ES256.'
                : sprintf('If the provider really signs with this algorithm, add it to oidc.connections.%s.algorithms; it must also be in the provider\'s id_token_signing_alg_values_supported.', $connection),
            'alg',
        );
    }

    public static function signatureInvalid(TokenKind $kind, string $connection, string $kid): self
    {
        return static::make(
            ErrorCode::TokenSignatureInvalid,
            sprintf('The signature of the %s of connection "%s" does not verify with the provider\'s key %s.', $kind->label(), $connection, self::shorten($kid)),
            'The token was changed on the way, or was not signed by this connection\'s provider. If the provider replaced a key without changing its kid, drop the cached key set with KeySetRepository::forget().',
            null,
        );
    }

    public static function issuerMismatch(TokenKind $kind, string $connection, string $problem): self
    {
        return static::make(
            ErrorCode::TokenIssuerMismatch,
            sprintf('The %s of connection "%s" %s.', $kind->label(), $connection, $problem),
            sprintf('If the provider changed its issuer, set oidc.connections.%s.issuer to the new value exactly. Otherwise the token comes from another provider and must not be used.', $connection),
            'iss',
        );
    }

    public static function audienceInvalid(TokenKind $kind, string $connection, string $problem, string $claim = 'aud'): self
    {
        return static::make(
            ErrorCode::TokenAudienceInvalid,
            sprintf('The %s of connection "%s" %s.', $kind->label(), $connection, $problem),
            sprintf('Check that oidc.connections.%s.client_id is the client the provider issues tokens to. A token for another client must not be used here.', $connection),
            $claim,
        );
    }

    public static function expired(TokenKind $kind, string $connection, int $secondsAgo, int $leeway): self
    {
        return static::make(
            ErrorCode::TokenExpired,
            sprintf('The %s of connection "%s" expired %d seconds ago (leeway %d seconds).', $kind->label(), $connection, $secondsAgo, $leeway),
            sprintf('Start the login again. If fresh tokens expire too, the server clock is off: run NTP. Raise oidc.connections.%s.leeway_seconds (at most 300) only for a known skew.', $connection),
            'exp',
        );
    }

    public static function notYetValid(TokenKind $kind, string $connection, string $claim, int $secondsAhead, int $leeway): self
    {
        return static::make(
            ErrorCode::TokenNotYetValid,
            sprintf('The %s of connection "%s" has %s %d seconds in the future (leeway %d seconds).', $kind->label(), $connection, $claim, $secondsAhead, $leeway),
            sprintf('The server clock and the provider\'s disagree: run NTP. Raise oidc.connections.%s.leeway_seconds (at most 300) only for a known skew.', $connection),
            $claim,
        );
    }

    public static function stale(TokenKind $kind, string $connection, int $age, int $maxAge): self
    {
        return static::make(
            ErrorCode::TokenStale,
            sprintf('The %s of connection "%s" was issued %d seconds ago, longer than the %d seconds a token may be old.', $kind->label(), $connection, $age, $maxAge),
            sprintf('Start the login again. A replayed token looks like this; so does a clock that is off. Raise oidc.connections.%s.max_token_age_seconds only if the provider issues tokens long before it returns them.', $connection),
            'iat',
        );
    }

    public static function claimInvalid(TokenKind $kind, string $connection, string $claim, string $problem): self
    {
        return static::make(
            ErrorCode::TokenClaimInvalid,
            sprintf('The %s of connection "%s" %s.', $kind->label(), $connection, $problem),
            sprintf('The provider sent the %s claim in a form the protocol does not allow. Check the claim configuration of the client at the provider.', $claim),
            $claim,
        );
    }

    public static function nonceMismatch(string $connection, bool $missing): self
    {
        return static::make(
            ErrorCode::IdTokenNonceMismatch,
            $missing
                ? sprintf('The ID token of connection "%s" has no nonce, although the login sent one.', $connection)
                : sprintf('The nonce of the ID token of connection "%s" is not the nonce of this login.', $connection),
            'Start the login again. The token belongs to another login: it was replayed, or two logins were mixed up.',
            'nonce',
        );
    }

    public static function authTimeInvalid(string $connection, string $problem, string $fix): self
    {
        return static::make(
            ErrorCode::IdTokenAuthTimeInvalid,
            sprintf('The ID token of connection "%s" %s.', $connection, $problem),
            $fix,
            'auth_time',
        );
    }

    public static function atHashMismatch(string $connection): self
    {
        return static::make(
            ErrorCode::IdTokenAtHashMismatch,
            sprintf('The at_hash of the ID token of connection "%s" does not match the access token it came with.', $connection),
            'Start the login again. The access token was swapped on the way, or the provider computes at_hash with another hash than OpenID Connect Core 3.1.3.6 prescribes.',
            'at_hash',
        );
    }

    /**
     * An ID token that came back from a refresh does not belong to the login
     * it renews (OpenID Connect Core 12.2).
     */
    public static function refreshMismatch(string $connection, string $claim, string $problem): self
    {
        return static::make(
            ErrorCode::RefreshedIdTokenMismatch,
            sprintf('The ID token the refresh of connection "%s" returned %s.', $connection, $problem),
            'Sign the person in again and drop the refresh token: a refreshed ID token must name the same issuer, subject and authentication as the login it renews, so this one belongs to someone or something else.',
            $claim,
        );
    }

    /** The claim or header member the failure is about, such as exp or alg; null when none is. */
    public function claim(): ?string
    {
        return $this->claim;
    }

    protected static function make(ErrorCode $code, string $problem, string $fix, ?string $claim): static
    {
        $exception = new static($code, $problem, $fix);
        $exception->claim = $claim;

        return $exception;
    }

    protected static function shorten(string $value): string
    {
        $value = (string) preg_replace('/[^\x20-\x7E]/', '?', $value);

        return strlen($value) > 100 ? substr($value, 0, 100).'...' : $value;
    }
}

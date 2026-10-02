<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
use DateTimeImmutable;
use Jose\Component\Checker\AudienceChecker;
use Jose\Component\Checker\ExpirationTimeChecker;
use Jose\Component\Checker\InvalidClaimException;
use Jose\Component\Checker\IsEqualChecker;
use Jose\Component\Checker\IssuedAtChecker;
use Jose\Component\Checker\IssuerChecker;
use Jose\Component\Checker\NotBeforeChecker;
use Jose\Component\Core\JWK;
use Psr\Clock\ClockInterface;

/**
 * The claim rules every token from the provider shares, whatever its kind:
 * iss, aud and azp, exp, nbf and iat, and the form of sub and other claims.
 * The ID token and logout token verifiers both run them, so a logout token is
 * held to the same issuer, audience and lifetime as an ID token (OpenID
 * Connect Back-Channel Logout 1.0, 2.6).
 *
 * iss, aud, azp, exp, nbf and iat are checked with web-token's claim
 * checkers, with the PSR-20 clock.
 *
 * @internal
 */
final readonly class ClaimChecks
{
    /** The latest timestamp read: 9999-12-31T23:59:59Z. */
    private const int MAX_TIMESTAMP = 253402300799;

    private const string GUID = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/D';

    public function __construct(private ClockInterface $clock) {}

    public function now(): int
    {
        return $this->clock->now()->getTimestamp();
    }

    /**
     * iss is the pinned issuer exactly; with an Entra {tenantid} issuer, the
     * issuer with the token's tid filled in. It must also equal
     * $responseIssuer when given, and the issuer member of the key that
     * signed the token when the key has one.
     *
     * @param  array<string, mixed>  $claims
     */
    public function issuer(TokenKind $kind, ConnectionConfig $config, ProviderMetadata $metadata, array $claims, JWK $key, ?string $responseIssuer = null): string
    {
        $iss = $claims['iss'] ?? null;

        if (! is_string($iss)) {
            throw TokenRejected::issuerMismatch($kind, $config->name, 'has no iss');
        }

        $tenantId = $config->hasTenantTemplate() ? $this->tenantId($kind, $config->name, $claims) : null;
        $expected = $tenantId === null ? $metadata->issuer : str_replace(ConnectionConfig::TENANT_TEMPLATE, $tenantId, $config->issuer);

        try {
            new IssuerChecker([$expected])->checkClaim($iss);
        } catch (InvalidClaimException) {
            throw TokenRejected::issuerMismatch($kind, $config->name, sprintf('names the issuer "%s", but the connection pins "%s"', self::shorten($iss), $expected));
        }

        if ($responseIssuer !== null && $responseIssuer !== $iss) {
            throw TokenRejected::issuerMismatch($kind, $config->name, sprintf('names the issuer "%s", but the callback named "%s" (RFC 9207)', self::shorten($iss), self::shorten($responseIssuer)));
        }

        // Microsoft Entra publishes an issuer on each key of its multi-tenant
        // key set; a key may only sign tokens of that issuer.
        if ($key->has('issuer')) {
            $keyIssuer = $key->get('issuer');
            $keyIssuer = is_string($keyIssuer) && is_string($claims['tid'] ?? null)
                ? str_replace(ConnectionConfig::TENANT_TEMPLATE, $claims['tid'], $keyIssuer)
                : $keyIssuer;

            if ($keyIssuer !== $iss) {
                throw TokenRejected::issuerMismatch($kind, $config->name, sprintf('names the issuer "%s", but the key that signed it is for %s', self::shorten($iss), is_string($keyIssuer) ? sprintf('"%s"', self::shorten($keyIssuer)) : 'a malformed issuer'));
            }
        }

        return $iss;
    }

    /**
     * aud contains the client id; with more than one audience azp is
     * required, and azp, when present, is the client id.
     *
     * @param  array<string, mixed>  $claims
     * @return non-empty-list<string>
     */
    public function audience(TokenKind $kind, ConnectionConfig $config, array $claims): array
    {
        $aud = $claims['aud'] ?? null;
        $audience = is_string($aud) ? [$aud] : $aud;

        if (! is_array($audience) || $audience === [] || ! array_is_list($audience) || array_filter($audience, is_string(...)) !== $audience) {
            throw TokenRejected::audienceInvalid($kind, $config->name, 'has no aud, or one that is not a string or a list of strings');
        }

        /** @var non-empty-list<string> $audience */
        try {
            new AudienceChecker($config->clientId)->checkClaim($aud);
        } catch (InvalidClaimException) {
            throw TokenRejected::audienceInvalid($kind, $config->name, sprintf('is not for the client "%s" (aud)', $config->clientId));
        }

        $azp = $claims['azp'] ?? null;

        if ($azp === null && count(array_unique($audience)) > 1) {
            throw TokenRejected::audienceInvalid($kind, $config->name, 'has several audiences and no azp, so it does not name the client it was issued to', 'azp');
        }

        if ($azp !== null) {
            try {
                new IsEqualChecker('azp', $config->clientId)->checkClaim($azp);
            } catch (InvalidClaimException) {
                throw TokenRejected::audienceInvalid($kind, $config->name, sprintf('was issued to another client (azp is not "%s")', $config->clientId), 'azp');
            }
        }

        return $audience;
    }

    /**
     * exp has not passed, nbf and iat are not in the future (each with the
     * connection's leeway), and iat is within max_token_age_seconds.
     *
     * @param  array<string, mixed>  $claims
     * @return array{int, int} iat and exp
     */
    public function lifetime(TokenKind $kind, ConnectionConfig $config, array $claims): array
    {
        $name = $config->name;
        $leeway = $config->leewaySeconds;
        $now = $this->now();

        $exp = $this->timestamp($kind, $name, $claims, 'exp', required: true);

        try {
            new ExpirationTimeChecker($this->clock, $leeway)->checkClaim($claims['exp']);
        } catch (InvalidClaimException) {
            throw TokenRejected::expired($kind, $name, $now - $exp, $leeway);
        }

        $nbf = $this->timestamp($kind, $name, $claims, 'nbf', required: false);

        if ($nbf !== null) {
            try {
                new NotBeforeChecker($this->clock, $leeway)->checkClaim($claims['nbf']);
            } catch (InvalidClaimException) {
                throw TokenRejected::notYetValid($kind, $name, 'nbf', $nbf - $now, $leeway);
            }
        }

        $iat = $this->timestamp($kind, $name, $claims, 'iat', required: true);

        try {
            new IssuedAtChecker($this->clock, $leeway)->checkClaim($claims['iat']);
        } catch (InvalidClaimException) {
            throw TokenRejected::notYetValid($kind, $name, 'iat', $iat - $now, $leeway);
        }

        if ($now - $iat > $config->maxTokenAgeSeconds + $leeway) {
            throw TokenRejected::stale($kind, $name, $now - $iat, $config->maxTokenAgeSeconds);
        }

        return [$iat, $exp];
    }

    /**
     * sub: 1 to 255 characters without control characters.
     *
     * @param  array<string, mixed>  $claims
     * @return ($required is true ? string : string|null)
     */
    public function subject(TokenKind $kind, string $connection, array $claims, bool $required = true): ?string
    {
        $sub = $claims['sub'] ?? null;

        if ($sub === null && ! $required) {
            return null;
        }

        // OpenID Connect Core 2: at most 255 ASCII characters. Control
        // characters are refused, so a subject is safe to log and compare.
        if (! self::validIdentifier($sub)) {
            throw TokenRejected::claimInvalid($kind, $connection, 'sub', 'has no sub, or one that is not 1 to 255 characters without control characters');
        }

        /** @var string $sub */
        return $sub;
    }

    /**
     * An optional claim that must be a string when present.
     *
     * @param  array<string, mixed>  $claims
     */
    public function optionalString(TokenKind $kind, string $connection, array $claims, string $claim): ?string
    {
        $value = $claims[$claim] ?? null;

        if ($value !== null && ! is_string($value)) {
            throw TokenRejected::claimInvalid($kind, $connection, $claim, sprintf('has a %s claim that is not a string', $claim));
        }

        return $value;
    }

    /**
     * A NumericDate claim (RFC 7519 2) in whole seconds.
     *
     * @param  array<string, mixed>  $claims
     * @return ($required is true ? int : int|null)
     */
    public function timestamp(TokenKind $kind, string $connection, array $claims, string $claim, bool $required): ?int
    {
        $value = $claims[$claim] ?? null;

        if ($value === null && ! $required) {
            return null;
        }

        if ((! is_int($value) && ! is_float($value)) || $value < 0 || $value > self::MAX_TIMESTAMP) {
            throw TokenRejected::claimInvalid($kind, $connection, $claim, $value === null
                ? sprintf('has no %s', $claim)
                : sprintf('has a %s that is not a time in seconds since 1970', $claim));
        }

        return (int) floor($value);
    }

    public static function date(int $timestamp): DateTimeImmutable
    {
        return new DateTimeImmutable('@'.$timestamp);
    }

    /**
     * Whether $value is 1 to 255 characters without control characters, the
     * form of sub, sid and jti the package accepts.
     */
    public static function validIdentifier(mixed $value): bool
    {
        return is_string($value) && strlen($value) <= 255 && preg_match('/^[^\x00-\x1F\x7F]{1,255}$/Du', $value) === 1;
    }

    public static function shorten(string $value): string
    {
        $value = (string) preg_replace('/[^\x20-\x7E]/', '?', $value);

        return strlen($value) > 200 ? substr($value, 0, 200).'...' : $value;
    }

    /**
     * The tid of a token of an Entra {tenantid} issuer: present, and a GUID.
     *
     * @param  array<string, mixed>  $claims
     */
    private function tenantId(TokenKind $kind, string $connection, array $claims): string
    {
        $tid = $claims['tid'] ?? null;

        if (! is_string($tid) || $tid === '') {
            throw TenantRejected::missing($connection, 'tid', $kind);
        }

        if (preg_match(self::GUID, $tid) !== 1) {
            throw TenantRejected::invalidTenant($connection, 'tid', 'is not a tenant id (a GUID)', $kind);
        }

        return $tid;
    }
}

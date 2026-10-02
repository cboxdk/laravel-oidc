<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\GroupsSource;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Config\TenantPolicy;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\OidcException;
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
use SensitiveParameter;

/**
 * Verifies an ID token (OpenID Connect Core 3.1.3.7) and returns its
 * {@see VerifiedClaims}. The checks run in this order, and the first that
 * fails throws a {@see TokenRejected} with its own code:
 *
 *  1. form, header, alg, key and signature ({@see SignedJwtReader});
 *  2. iss is the pinned issuer exactly; with an Entra {tenantid} issuer, the
 *     issuer with the token's tid filled in. It must also equal the callback's
 *     iss parameter when there was one, and the issuer member of the key that
 *     signed it when the key has one;
 *  3. aud contains the client id; with more than one audience azp is
 *     required, and azp, when present, is the client id;
 *  4. exp has not passed, nbf and iat are not in the future (each with the
 *     connection's leeway), and iat is within max_token_age_seconds;
 *  5. nonce is the login's nonce;
 *  6. sub is 1 to 255 characters without control characters;
 *  7. auth_time is not in the future, and is required and within max_age
 *     when the login sent max_age;
 *  8. at_hash, when present, is the hash of the access token;
 *  9. the tenant claim (Entra tid, Google hd) is present and allowed;
 * 10. amr, acr, sid and groups have the form the protocol gives them.
 *
 * iss, aud, azp, exp, nbf and iat are checked with web-token's claim
 * checkers, with the PSR-20 clock.
 */
final readonly class IdTokenVerifier
{
    /** The latest timestamp read: 9999-12-31T23:59:59Z. */
    private const int MAX_TIMESTAMP = 253402300799;

    private const string GUID = '/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/D';

    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private SignedJwtReader $reader,
        private ClockInterface $clock,
    ) {}

    /**
     * @param  ConnectionConfig|string|null  $connection  a connection, its name, or null for the default
     *
     * @throws TokenRejected
     * @throws OidcException when discovery or the key set cannot be loaded, or no key fits
     */
    public function verify(ConnectionConfig|string|null $connection, #[SensitiveParameter] string $idToken, IdTokenExpectations $expected): VerifiedClaims
    {
        $config = $connection instanceof ConnectionConfig ? $connection : $this->config->connection($connection);
        $metadata = $this->metadata->for($config);
        $jwt = $this->reader->read($config, $metadata, TokenKind::IdToken, $idToken);
        $claims = $jwt->claims;
        $name = $config->name;
        $now = $this->clock->now()->getTimestamp();

        $issuer = $this->issuer($config, $metadata, $claims, $jwt->key, $expected->responseIssuer);
        $audience = $this->audience($config, $claims);
        [$issuedAt, $expiresAt] = $this->lifetime($config, $claims, $now);
        $this->nonce($name, $claims, $expected->nonce);
        $subject = $this->subject($name, $claims);
        $authTime = $this->authTime($config, $claims, $expected->maxAge, $now);
        $this->accessTokenHash($name, $claims, $jwt->algorithm, $expected->accessToken);
        $tenant = $this->tenant($config, $claims);
        [$groups, $overage] = $this->groups($config, $claims);

        return new VerifiedClaims(
            connection: $name,
            issuer: $issuer,
            subject: $subject,
            audience: $audience,
            authorizedParty: is_string($claims['azp'] ?? null) ? $claims['azp'] : null,
            issuedAt: $this->date($issuedAt),
            expiresAt: $this->date($expiresAt),
            authTime: $authTime === null ? null : $this->date($authTime),
            authenticationMethods: $this->authenticationMethods($name, $claims),
            authenticationContext: $this->optionalString($name, $claims, 'acr'),
            sessionId: $this->optionalString($name, $claims, 'sid'),
            tenant: $tenant,
            groups: $groups,
            groupsOverage: $overage,
            claims: $claims,
        );
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function issuer(ConnectionConfig $config, ProviderMetadata $metadata, array $claims, JWK $key, ?string $responseIssuer): string
    {
        $kind = TokenKind::IdToken;
        $iss = $claims['iss'] ?? null;

        if (! is_string($iss)) {
            throw TokenRejected::issuerMismatch($kind, $config->name, 'has no iss');
        }

        $tenantId = $config->hasTenantTemplate() ? $this->tenantId($config->name, $claims) : null;
        $expected = $tenantId === null ? $metadata->issuer : str_replace(ConnectionConfig::TENANT_TEMPLATE, $tenantId, $config->issuer);

        try {
            new IssuerChecker([$expected])->checkClaim($iss);
        } catch (InvalidClaimException) {
            throw TokenRejected::issuerMismatch($kind, $config->name, sprintf('names the issuer "%s", but the connection pins "%s"', $this->shorten($iss), $expected));
        }

        if ($responseIssuer !== null && $responseIssuer !== $iss) {
            throw TokenRejected::issuerMismatch($kind, $config->name, sprintf('names the issuer "%s", but the callback named "%s" (RFC 9207)', $this->shorten($iss), $this->shorten($responseIssuer)));
        }

        // Microsoft Entra publishes an issuer on each key of its multi-tenant
        // key set; a key may only sign tokens of that issuer.
        if ($key->has('issuer')) {
            $keyIssuer = $key->get('issuer');
            $keyIssuer = is_string($keyIssuer) && is_string($claims['tid'] ?? null)
                ? str_replace(ConnectionConfig::TENANT_TEMPLATE, $claims['tid'], $keyIssuer)
                : $keyIssuer;

            if ($keyIssuer !== $iss) {
                throw TokenRejected::issuerMismatch($kind, $config->name, sprintf('names the issuer "%s", but the key that signed it is for %s', $this->shorten($iss), is_string($keyIssuer) ? sprintf('"%s"', $this->shorten($keyIssuer)) : 'a malformed issuer'));
            }
        }

        return $iss;
    }

    /**
     * The tid of a token of an Entra {tenantid} issuer: present, and a GUID.
     *
     * @param  array<string, mixed>  $claims
     */
    private function tenantId(string $connection, array $claims): string
    {
        $tid = $claims['tid'] ?? null;

        if (! is_string($tid) || $tid === '') {
            throw TenantRejected::missing($connection, 'tid');
        }

        if (preg_match(self::GUID, $tid) !== 1) {
            throw TenantRejected::invalidTenant($connection, 'tid', 'is not a tenant id (a GUID)');
        }

        return $tid;
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return non-empty-list<string>
     */
    private function audience(ConnectionConfig $config, array $claims): array
    {
        $kind = TokenKind::IdToken;
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
     * exp, nbf and iat, with the connection's leeway.
     *
     * @param  array<string, mixed>  $claims
     * @return array{int, int} iat and exp
     */
    private function lifetime(ConnectionConfig $config, array $claims, int $now): array
    {
        $kind = TokenKind::IdToken;
        $name = $config->name;
        $leeway = $config->leewaySeconds;

        $exp = $this->timestamp($name, $claims, 'exp', required: true);

        try {
            new ExpirationTimeChecker($this->clock, $leeway)->checkClaim($claims['exp']);
        } catch (InvalidClaimException) {
            throw TokenRejected::expired($kind, $name, $now - $exp, $leeway);
        }

        $nbf = $this->timestamp($name, $claims, 'nbf', required: false);

        if ($nbf !== null) {
            try {
                new NotBeforeChecker($this->clock, $leeway)->checkClaim($claims['nbf']);
            } catch (InvalidClaimException) {
                throw TokenRejected::notYetValid($kind, $name, 'nbf', $nbf - $now, $leeway);
            }
        }

        $iat = $this->timestamp($name, $claims, 'iat', required: true);

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
     * @param  array<string, mixed>  $claims
     */
    private function nonce(string $connection, array $claims, ?string $expected): void
    {
        if ($expected === null) {
            return;
        }

        $nonce = $claims['nonce'] ?? null;

        if (! is_string($nonce)) {
            throw TokenRejected::nonceMismatch($connection, missing: true);
        }

        if (! hash_equals($expected, $nonce)) {
            throw TokenRejected::nonceMismatch($connection, missing: false);
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function subject(string $connection, array $claims): string
    {
        $sub = $claims['sub'] ?? null;

        // OpenID Connect Core 2: at most 255 ASCII characters. Control
        // characters are refused, so a subject is safe to log and compare.
        if (! is_string($sub) || preg_match('/^[^\x00-\x1F\x7F]{1,255}$/Du', $sub) !== 1 || strlen($sub) > 255) {
            throw TokenRejected::claimInvalid(TokenKind::IdToken, $connection, 'sub', 'has no sub, or one that is not 1 to 255 characters without control characters');
        }

        return $sub;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function authTime(ConnectionConfig $config, array $claims, ?int $maxAge, int $now): ?int
    {
        $name = $config->name;
        $leeway = $config->leewaySeconds;
        $authTime = $this->timestamp($name, $claims, 'auth_time', required: false);

        if ($authTime === null) {
            if ($maxAge !== null) {
                throw TokenRejected::authTimeInvalid($name, sprintf('has no auth_time, although the login sent max_age %d', $maxAge), 'Use a provider that returns auth_time when max_age is sent (OpenID Connect Core 3.1.2.1), or do not send max_age to it.');
            }

            return null;
        }

        if ($authTime - $now > $leeway) {
            throw TokenRejected::authTimeInvalid($name, sprintf('says the person signed in %d seconds in the future (leeway %d seconds)', $authTime - $now, $leeway), 'The server clock and the provider\'s disagree: run NTP.');
        }

        if ($maxAge !== null && $now - $authTime > $maxAge + $leeway) {
            throw TokenRejected::authTimeInvalid($name, sprintf('says the person signed in %d seconds ago, longer than the max_age of %d seconds', $now - $authTime, $maxAge), 'Start the login again; the provider did not ask the person to sign in again as max_age requires.');
        }

        return $authTime;
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function accessTokenHash(string $connection, array $claims, SigningAlgorithm $algorithm, ?string $accessToken): void
    {
        if (! array_key_exists('at_hash', $claims) || $accessToken === null) {
            return;
        }

        $atHash = $claims['at_hash'];

        if (! is_string($atHash) || ! hash_equals($algorithm->accessTokenHash($accessToken), $atHash)) {
            throw TokenRejected::atHashMismatch($connection);
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function tenant(ConnectionConfig $config, array $claims): ?string
    {
        $policy = $config->tenant;

        if (! $policy instanceof TenantPolicy) {
            return null;
        }

        $tenant = $claims[$policy->claim] ?? null;

        if (! is_string($tenant) || $tenant === '') {
            throw TenantRejected::missing($config->name, $policy->claim);
        }

        if (! $policy->allows($tenant)) {
            throw TenantRejected::notAllowed($config->name, $policy->claim, $tenant);
        }

        return $tenant;
    }

    /**
     * The groups of the configured claim, and whether the provider left them
     * out for being too many (Entra's overage: _claim_names names the claim).
     *
     * @param  array<string, mixed>  $claims
     * @return array{list<string>|null, bool}
     */
    private function groups(ConnectionConfig $config, array $claims): array
    {
        if ($config->groups->source !== GroupsSource::IdToken) {
            return [null, false];
        }

        $claim = $config->groups->claim;
        $names = $claims['_claim_names'] ?? null;

        if (is_array($names) && array_key_exists($claim, $names)) {
            return [null, true];
        }

        if (! array_key_exists($claim, $claims)) {
            return [[], false];
        }

        $groups = $claims[$claim];

        if (! is_array($groups) || ! array_is_list($groups) || array_filter($groups, is_string(...)) !== $groups) {
            throw TokenRejected::claimInvalid(TokenKind::IdToken, $config->name, $claim, sprintf('has a %s claim that is not a list of strings', $claim));
        }

        /** @var list<string> $groups */
        return [array_values(array_unique($groups)), false];
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return list<string>|null
     */
    private function authenticationMethods(string $connection, array $claims): ?array
    {
        if (! array_key_exists('amr', $claims)) {
            return null;
        }

        $amr = $claims['amr'];

        if (! is_array($amr) || ! array_is_list($amr) || array_filter($amr, is_string(...)) !== $amr) {
            throw TokenRejected::claimInvalid(TokenKind::IdToken, $connection, 'amr', 'has an amr claim that is not a list of strings');
        }

        /** @var list<string> $amr */
        return array_values(array_unique($amr));
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function optionalString(string $connection, array $claims, string $claim): ?string
    {
        $value = $claims[$claim] ?? null;

        if ($value !== null && ! is_string($value)) {
            throw TokenRejected::claimInvalid(TokenKind::IdToken, $connection, $claim, sprintf('has a %s claim that is not a string', $claim));
        }

        return $value;
    }

    /**
     * A NumericDate claim (RFC 7519 2) in whole seconds.
     *
     * @param  array<string, mixed>  $claims
     * @return ($required is true ? int : int|null)
     */
    private function timestamp(string $connection, array $claims, string $claim, bool $required): ?int
    {
        $value = $claims[$claim] ?? null;

        if ($value === null && ! $required) {
            return null;
        }

        if ((! is_int($value) && ! is_float($value)) || $value < 0 || $value > self::MAX_TIMESTAMP) {
            throw TokenRejected::claimInvalid(TokenKind::IdToken, $connection, $claim, $value === null
                ? sprintf('has no %s', $claim)
                : sprintf('has a %s that is not a time in seconds since 1970', $claim));
        }

        return (int) floor($value);
    }

    private function date(int $timestamp): DateTimeImmutable
    {
        return new DateTimeImmutable('@'.$timestamp);
    }

    private function shorten(string $value): string
    {
        $value = (string) preg_replace('/[^\x20-\x7E]/', '?', $value);

        return strlen($value) > 200 ? substr($value, 0, 200).'...' : $value;
    }
}

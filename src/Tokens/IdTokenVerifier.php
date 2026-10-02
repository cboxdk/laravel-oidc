<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\GroupsSource;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Config\TenantPolicy;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
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
 * 10. amr, acr, sid and groups have the form the protocol gives them;
 * 11. acr is one of the login's acr_values when it sent some;
 * 12. for a token a refresh returned ({@see IdTokenExpectations::forRefresh()}),
 *     iss, sub and the tenant are those of the login it renews, and auth_time
 *     and nonce, when present, too (OpenID Connect Core 12.2).
 *
 * iss, aud, azp, exp, nbf and iat are checked with web-token's claim
 * checkers, with the PSR-20 clock ({@see ClaimChecks}).
 */
final readonly class IdTokenVerifier
{
    private const TokenKind KIND = TokenKind::IdToken;

    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private SignedJwtReader $reader,
        private ClaimChecks $checks,
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
        $jwt = $this->reader->read($config, $metadata, self::KIND, $idToken);
        $claims = $jwt->claims;
        $name = $config->name;
        $now = $this->checks->now();

        $issuer = $this->checks->issuer(self::KIND, $config, $metadata, $claims, $jwt->key, $expected->responseIssuer);
        $audience = $this->checks->audience(self::KIND, $config, $claims);
        [$issuedAt, $expiresAt] = $this->checks->lifetime(self::KIND, $config, $claims);
        $this->nonce($name, $claims, $expected->nonce);
        $subject = $this->checks->subject(self::KIND, $name, $claims);
        $authTime = $this->authTime($config, $claims, $expected->maxAge, $now);
        $this->accessTokenHash($name, $claims, $jwt->algorithm, $expected->accessToken);
        $tenant = $this->tenant($config, $claims);
        [$groups, $overage] = $this->groups($config, $claims);
        $authenticationMethods = $this->authenticationMethods($name, $claims);
        $authenticationContext = $this->checks->optionalString(self::KIND, $name, $claims, 'acr');
        $sessionId = $this->checks->optionalString(self::KIND, $name, $claims, 'sid');
        $this->authenticationContext($name, $authenticationContext, $expected->acrValues);

        if ($expected->renews instanceof VerifiedClaims) {
            $this->continuity($config, $expected->renews, $issuer, $subject, $tenant, $authTime, $claims);
        }

        return new VerifiedClaims(
            connection: $name,
            issuer: $issuer,
            subject: $subject,
            audience: $audience,
            authorizedParty: is_string($claims['azp'] ?? null) ? $claims['azp'] : null,
            issuedAt: ClaimChecks::date($issuedAt),
            expiresAt: ClaimChecks::date($expiresAt),
            authTime: $authTime === null ? null : ClaimChecks::date($authTime),
            authenticationMethods: $authenticationMethods,
            authenticationContext: $authenticationContext,
            sessionId: $sessionId,
            tenant: $tenant,
            groups: $groups,
            groupsOverage: $overage,
            claims: $claims,
        );
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
     * @param  list<string>  $requested
     */
    private function authenticationContext(string $connection, ?string $acr, array $requested): void
    {
        if ($requested !== [] && ($acr === null || ! in_array($acr, $requested, true))) {
            throw TokenRejected::acrMismatch($connection, $acr, $requested);
        }
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function authTime(ConnectionConfig $config, array $claims, ?int $maxAge, int $now): ?int
    {
        $name = $config->name;
        $leeway = $config->leewaySeconds;
        $authTime = $this->checks->timestamp(self::KIND, $name, $claims, 'auth_time', required: false);

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
            throw TokenRejected::claimInvalid(self::KIND, $config->name, $claim, sprintf('has a %s claim that is not a list of strings', $claim));
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
            throw TokenRejected::claimInvalid(self::KIND, $connection, 'amr', 'has an amr claim that is not a list of strings');
        }

        /** @var list<string> $amr */
        return array_values(array_unique($amr));
    }

    /**
     * OpenID Connect Core 12.2: an ID token a refresh returns belongs to the
     * login it renews. iss and sub must be the same; so must the tenant when
     * the connection pins one; auth_time, when present, must still be the
     * time of the original sign-in; and a nonce, when present, must be the
     * original one.
     *
     * @param  array<string, mixed>  $claims
     */
    private function continuity(ConnectionConfig $config, VerifiedClaims $original, string $issuer, string $subject, ?string $tenant, ?int $authTime, array $claims): void
    {
        $name = $config->name;

        if ($original->connection !== $name) {
            throw TokenRejected::refreshMismatch($name, 'iss', sprintf('renews a login of connection "%s"', $original->connection));
        }

        if ($issuer !== $original->issuer) {
            throw TokenRejected::refreshMismatch($name, 'iss', sprintf('names the issuer "%s", but the login it renews was issued by "%s"', ClaimChecks::shorten($issuer), $original->issuer));
        }

        if ($subject !== $original->subject) {
            throw TokenRejected::refreshMismatch($name, 'sub', 'names another subject than the login it renews');
        }

        if ($original->tenant !== null && ($tenant === null || strcasecmp($tenant, $original->tenant) !== 0)) {
            throw TokenRejected::refreshMismatch($name, (string) $config->tenant?->claim, 'names another tenant than the login it renews');
        }

        if ($authTime !== null && $original->authTime instanceof \DateTimeImmutable && $authTime !== $original->authTime->getTimestamp()) {
            throw TokenRejected::refreshMismatch($name, 'auth_time', sprintf('says the person signed in at %d, but the login it renews signed in at %d', $authTime, $original->authTime->getTimestamp()));
        }

        if (array_key_exists('nonce', $claims)) {
            $nonce = $claims['nonce'];
            $originalNonce = $original->claims['nonce'] ?? null;

            if (! is_string($nonce) || ! is_string($originalNonce) || ! hash_equals($originalNonce, $nonce)) {
                throw TokenRejected::refreshMismatch($name, 'nonce', 'has another nonce than the login it renews');
            }
        }
    }
}

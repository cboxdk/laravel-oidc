<?php

declare(strict_types=1);

namespace Cbox\Oidc\Discovery;

use Cbox\Oidc\Config\ClientAssertionConfig;
use Cbox\Oidc\Config\ClientAuthMethod;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Support\HttpsUrl;
use Cbox\Oidc\Tokens\SigningAlgorithm;

/**
 * A provider's discovery document (OpenID Connect Discovery 1.0, RFC 8414),
 * checked against the connection it was fetched for.
 *
 * {@see self::fromDocument()} refuses a document whose issuer is not the
 * pinned one, that lacks an endpoint the flow needs, that names an endpoint
 * other than an https URL, or that cannot work with the connection: no common
 * signing algorithm, no PKCE S256, no code response type, or not the client
 * authentication the connection uses.
 */
final readonly class ProviderMetadata
{
    /**
     * @param  non-empty-list<SigningAlgorithm>  $signingAlgorithms  the connection's algorithms the provider also lists, in the connection's order
     * @param  array<array-key, mixed>  $document  the whole document as served
     */
    public function __construct(
        public string $issuer,
        public string $authorizationEndpoint,
        public string $tokenEndpoint,
        public string $jwksUri,
        public ?string $userinfoEndpoint,
        public ?string $endSessionEndpoint,
        public ?string $revocationEndpoint,
        public array $signingAlgorithms,
        public bool $authorizationResponseIssParameterSupported,
        public bool $backchannelLogoutSupported,
        public bool $backchannelLogoutSessionSupported,
        public array $document,
    ) {}

    /**
     * @param  array<array-key, mixed>  $document
     *
     * @throws DiscoveryFailed
     */
    public static function fromDocument(array $document, ConnectionConfig $connection): self
    {
        $invalid = static fn (string $problem, string $fix): DiscoveryFailed => DiscoveryFailed::invalid($connection->name, $connection->discoveryUrl, $problem, $fix);

        $issuer = $document['issuer'] ?? null;

        if (! is_string($issuer)) {
            throw $invalid('has no issuer', 'Check that discovery_url points at the provider\'s openid-configuration document.');
        }

        // RFC 8414 3.3 and OpenID Connect Discovery 4.3: exactly equal. No
        // trailing-slash or case tolerance; a document for another issuer
        // would send codes and secrets to another party.
        if ($issuer !== $connection->issuer) {
            throw DiscoveryFailed::issuerMismatch($connection->name, $connection->issuer, $issuer);
        }

        $endpoint = static function (string $name, bool $required) use ($document, $invalid, $connection): ?string {
            $value = $document[$name] ?? null;

            if ($value === null && ! $required) {
                return null;
            }

            if (! HttpsUrl::valid($value, $connection->allowInsecureHttp)) {
                throw $invalid(
                    $value === null ? sprintf('has no %s', $name) : sprintf('has %s set to something other than an https URL', $name),
                    sprintf('The provider must publish %s as an absolute https URL; the package calls nothing else.', $name),
                );
            }

            /** @var string $value */
            return $value;
        };

        $authorizationEndpoint = (string) $endpoint('authorization_endpoint', true);
        $tokenEndpoint = (string) $endpoint('token_endpoint', true);
        $jwksUri = (string) $endpoint('jwks_uri', true);
        $userinfoEndpoint = $endpoint('userinfo_endpoint', false);
        $endSessionEndpoint = $endpoint('end_session_endpoint', false);
        $revocationEndpoint = $endpoint('revocation_endpoint', false);

        $algorithms = self::signingAlgorithms($document, $connection, $invalid);
        self::assertSupports($document, 'response_types_supported', 'code', 'does not support the authorization code flow (response_types_supported lacks "code")', 'Use a provider (or client registration) that supports response_type=code.', $invalid);
        self::assertSupports($document, 'code_challenge_methods_supported', 'S256', 'does not support PKCE with S256 (code_challenge_methods_supported lacks "S256")', 'Enable PKCE S256 at the provider; the package always sends it.', $invalid);
        self::assertClientAuth($document, $connection, $invalid);

        return new self(
            issuer: $issuer,
            authorizationEndpoint: $authorizationEndpoint,
            tokenEndpoint: $tokenEndpoint,
            jwksUri: $jwksUri,
            userinfoEndpoint: $userinfoEndpoint,
            endSessionEndpoint: $endSessionEndpoint,
            revocationEndpoint: $revocationEndpoint,
            signingAlgorithms: $algorithms,
            authorizationResponseIssParameterSupported: ($document['authorization_response_iss_parameter_supported'] ?? false) === true,
            backchannelLogoutSupported: ($document['backchannel_logout_supported'] ?? false) === true,
            backchannelLogoutSessionSupported: ($document['backchannel_logout_session_supported'] ?? false) === true,
            document: $document,
        );
    }

    public function supports(SigningAlgorithm $algorithm): bool
    {
        return in_array($algorithm, $this->signingAlgorithms, true);
    }

    /**
     * @param  array<array-key, mixed>  $document
     * @param  callable(string, string): DiscoveryFailed  $invalid
     */
    private static function assertClientAuth(array $document, ConnectionConfig $connection, callable $invalid): void
    {
        // A public client sends no secret, so there is nothing to agree on.
        if ($connection->clientAuth === ClientAuthMethod::None) {
            return;
        }

        $fix = sprintf('Set oidc.connections.%s.client_auth to a method the provider lists.', $connection->name);

        if ($connection->clientAssertion instanceof ClientAssertionConfig) {
            $algorithm = $connection->clientAssertion->algorithm->value;
            self::assertSupports($document, 'token_endpoint_auth_signing_alg_values_supported', $algorithm, sprintf('does not accept client assertions signed with %s (token_endpoint_auth_signing_alg_values_supported)', $algorithm), sprintf('Set oidc.connections.%s.client_assertion.algorithm to an algorithm the provider lists, with a key that fits it.', $connection->name), $invalid);
        }

        if (array_key_exists('token_endpoint_auth_methods_supported', $document)) {
            self::assertSupports($document, 'token_endpoint_auth_methods_supported', $connection->clientAuth->value, sprintf('does not support client_auth %s (token_endpoint_auth_methods_supported)', $connection->clientAuth->value), $fix, $invalid);

            return;
        }

        // Absent, the provider supports client_secret_basic only (Discovery 3).
        if ($connection->clientAuth !== ClientAuthMethod::ClientSecretBasic) {
            throw $invalid(sprintf('lists no token_endpoint_auth_methods_supported, which means client_secret_basic only, but the connection uses %s', $connection->clientAuth->value), $fix);
        }
    }

    /**
     * @param  array<array-key, mixed>  $document
     * @param  callable(string, string): DiscoveryFailed  $invalid
     * @return non-empty-list<SigningAlgorithm>
     */
    private static function signingAlgorithms(array $document, ConnectionConfig $connection, callable $invalid): array
    {
        $advertised = self::stringList($document['id_token_signing_alg_values_supported'] ?? null);

        if ($advertised === null || $advertised === []) {
            throw $invalid('has no id_token_signing_alg_values_supported', 'The provider must list the algorithms it signs ID tokens with (OpenID Connect Discovery 3).');
        }

        $common = array_values(array_filter(
            $connection->algorithms,
            static fn (SigningAlgorithm $algorithm): bool => in_array($algorithm->value, $advertised, true),
        ));

        if ($common === []) {
            throw $invalid(
                sprintf('lists no ID token algorithm the connection accepts (it lists %s)', implode(', ', array_slice($advertised, 0, 10))),
                sprintf('Add one of the provider\'s algorithms to oidc.connections.%s.algorithms, if the package supports it.', $connection->name),
            );
        }

        return $common;
    }

    /**
     * Checks an optional list member: absent is fine, present it must be a
     * list of strings that contains $needle.
     *
     * @param  array<array-key, mixed>  $document
     * @param  callable(string, string): DiscoveryFailed  $invalid
     */
    private static function assertSupports(array $document, string $key, string $needle, string $problem, string $fix, callable $invalid): void
    {
        if (! array_key_exists($key, $document)) {
            return;
        }

        $values = self::stringList($document[$key]);

        if ($values === null) {
            throw $invalid(sprintf('has %s set to something other than a list of strings', $key), 'Check the provider\'s discovery document.');
        }

        if (! in_array($needle, $values, true)) {
            throw $invalid($problem, $fix);
        }
    }

    /**
     * @return list<string>|null
     */
    private static function stringList(mixed $value): ?array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return null;
        }

        foreach ($value as $item) {
            if (! is_string($item)) {
                return null;
            }
        }

        /** @var list<string> $value */
        return $value;
    }
}

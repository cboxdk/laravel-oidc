<?php

declare(strict_types=1);

namespace Cbox\Oidc\Diagnostics;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\GroupsSource;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Config\TenantPolicy;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Keys\KeySelector;
use Cbox\Oidc\Keys\KeySet;
use Cbox\Oidc\Support\ProviderDocument;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Illuminate\Contracts\Container\Container;
use Jose\Component\Core\JWK;

/**
 * Checks a connection against its provider without signing anyone in: the
 * configuration, the discovery document, the key set, and the endpoints the
 * package's calls need. What `php artisan oidc:check` prints.
 *
 * The discovery document and the key set are fetched afresh, through the
 * same client, SSRF guard and checks as a login, and the cache is left as it
 * is: a provider that is down during a check keeps its cached copies for the
 * logins that need them. The client secret is not tried: the token endpoint
 * is only called with a code, so a wrong secret shows at the first login
 * (oidc_token_request_rejected, invalid_client).
 */
final readonly class ConnectionDiagnostics
{
    /**
     * The services are resolved per call: they need a valid configuration,
     * which is the first thing a diagnosis checks.
     */
    public function __construct(private Container $container) {}

    /**
     * The configured connection names.
     *
     * @return list<string>
     *
     * @throws OidcException when the configuration is invalid
     */
    public function connections(): array
    {
        return $this->container->make(OidcConfig::class)->names();
    }

    public function diagnose(?string $connection = null): Diagnosis
    {
        try {
            $config = $this->container->make(OidcConfig::class)->connection($connection);
        } catch (OidcException $exception) {
            return new Diagnosis($connection ?? 'default', [Finding::failed('configuration', $exception)]);
        }

        $findings = $this->configuration($config);

        try {
            $response = $this->container->make(HttpClient::class)->send(HttpRequest::get($config->discoveryUrl, ['Accept' => 'application/json']));
            $metadata = ProviderMetadata::fromDocument(ProviderDocument::fromResponse($response, $config->discoveryUrl, 'discovery document'), $config);
        } catch (OidcException $exception) {
            return new Diagnosis($config->name, [...$findings, Finding::failed('discovery', $exception)]);
        }

        return new Diagnosis($config->name, [
            ...$findings,
            Finding::pass('discovery', sprintf('%s names the pinned issuer %s.', $config->discoveryUrl, $metadata->issuer)),
            Finding::pass('algorithms', sprintf('ID tokens may be signed with %s.', $this->algorithms($metadata->signingAlgorithms))),
            ...$this->keys($config, $metadata),
            ...$this->endpoints($config, $metadata),
        ]);
    }

    /**
     * @return list<Finding>
     */
    private function configuration(ConnectionConfig $config): array
    {
        $findings = [Finding::pass('configuration', sprintf('Issuer %s, client %s, client_auth %s.', $config->issuer, $config->clientId, $config->clientAuth->value))];

        $scheme = parse_url($config->redirectUri, PHP_URL_SCHEME);
        $host = parse_url($config->redirectUri, PHP_URL_HOST);

        if ($scheme === 'http' && is_string($host) && ! $this->localHost($host)) {
            $findings[] = Finding::warn(
                'redirect_uri',
                sprintf('%s uses http on a host that is not local; the code travels unencrypted, and most providers refuse it.', $config->redirectUri),
                sprintf('Set oidc.connections.%s.redirect_uri to an https URL, and register that one at the provider.', $config->name),
            );
        }

        if ($config->tenant instanceof TenantPolicy) {
            $findings[] = $config->tenant->allowsAny()
                ? Finding::warn('tenant', sprintf('Any value of the %s claim is accepted; every organisation of the provider can sign in.', $config->tenant->claim), sprintf('List the tenants you accept in oidc.connections.%s.tenant.allowed, unless any organisation may sign in on purpose.', $config->name))
                : Finding::pass('tenant', sprintf('ID tokens must carry %s with one of: %s.', $config->tenant->claim, implode(', ', $config->tenant->allowed)));
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private function keys(ConnectionConfig $config, ProviderMetadata $metadata): array
    {
        try {
            $response = $this->container->make(HttpClient::class)->send(HttpRequest::get($metadata->jwksUri, ['Accept' => 'application/jwk-set+json, application/json']));
            $keys = KeySet::fromDocument(ProviderDocument::fromResponse($response, $metadata->jwksUri, 'key set'), $config->name, $metadata->jwksUri)->keys;
        } catch (OidcException $exception) {
            return [Finding::failed('keys', $exception)];
        }

        $selector = $this->container->make(KeySelector::class);
        $usable = array_values(array_filter($keys, fn (JWK $key): bool => $this->usable($selector, $key, $metadata->signingAlgorithms)));

        if ($usable === []) {
            return [Finding::fail(
                'keys',
                $keys === []
                    ? sprintf('The key set at %s has no key the package can read.', $metadata->jwksUri)
                    : sprintf('None of the %d keys at %s may verify a token signed with %s: %s.', count($keys), $metadata->jwksUri, $this->algorithms($metadata->signingAlgorithms), $this->firstProblem($selector, $keys[0], $metadata->signingAlgorithms[0])),
                sprintf('Check that oidc.connections.%s.algorithms lists the algorithm the provider signs ID tokens with, and that the provider publishes its signing keys at jwks_uri.', $config->name),
                ErrorCode::SigningKeyNotFound,
            )];
        }

        $findings = [Finding::pass('keys', sprintf('%d of the %d keys at %s may verify ID tokens.', count($usable), count($keys), $metadata->jwksUri))];
        $withoutKid = array_filter($usable, static fn (JWK $key): bool => ! $key->has('kid'));

        if (count($usable) > 1 && $withoutKid !== []) {
            $findings[] = Finding::warn(
                'keys',
                sprintf('%d usable keys have no kid; a token without a kid matches none of them when several fit.', count($withoutKid)),
                'Ask the provider to publish a kid on every key; tokens that name a kid are not affected.',
            );
        }

        return $findings;
    }

    /**
     * @return list<Finding>
     */
    private function endpoints(ConnectionConfig $config, ProviderMetadata $metadata): array
    {
        $findings = [];

        if ($metadata->userinfoEndpoint !== null) {
            $findings[] = Finding::pass('userinfo', sprintf('Userinfo is at %s.', $metadata->userinfoEndpoint));
        } elseif ($config->groups->source === GroupsSource::UserInfo) {
            $findings[] = Finding::fail(
                'userinfo',
                'The provider has no userinfo_endpoint, and the connection reads its groups from userinfo, so every login would fail.',
                sprintf('Set oidc.connections.%s.groups.source to id_token or none.', $config->name),
                ErrorCode::EndpointNotSupported,
            );
        } else {
            $findings[] = Finding::note('userinfo', 'The provider has no userinfo_endpoint; Oidc::userInfo() is not available.');
        }

        $findings[] = $metadata->endSessionEndpoint !== null
            ? Finding::pass('logout', sprintf('RP-initiated logout goes to %s.', $metadata->endSessionEndpoint))
            : Finding::note('logout', 'The provider has no end_session_endpoint; Oidc::logout() redirects to your fallback URL, and the provider session stays.');

        $findings[] = $metadata->revocationEndpoint !== null
            ? Finding::pass('revocation', sprintf('Tokens are revoked at %s.', $metadata->revocationEndpoint))
            : Finding::note('revocation', 'The provider has no revocation_endpoint; Oidc::revoke() is not available.');

        $findings[] = $metadata->backchannelLogoutSupported
            ? Finding::pass('back-channel', $metadata->backchannelLogoutSessionSupported ? 'The provider announces back-channel logout, with sid.' : 'The provider announces back-channel logout, without sid.')
            : Finding::note('back-channel', 'The provider does not announce back-channel logout (backchannel_logout_supported).');

        $findings[] = $metadata->authorizationResponseIssParameterSupported
            ? Finding::pass('iss parameter', 'The provider announces the iss callback parameter (RFC 9207); a callback without it is refused.')
            : Finding::note('iss parameter', 'The provider does not announce the iss callback parameter (RFC 9207); it is checked when a callback carries it.');

        return $findings;
    }

    /**
     * @param  non-empty-list<SigningAlgorithm>  $algorithms
     */
    private function usable(KeySelector $selector, JWK $key, array $algorithms): bool
    {
        return array_any($algorithms, fn (SigningAlgorithm $algorithm): bool => $selector->problems($key, $algorithm) === []);
    }

    private function firstProblem(KeySelector $selector, JWK $key, SigningAlgorithm $algorithm): string
    {
        $kid = $key->has('kid') && is_string($key->get('kid')) ? sprintf('key "%s"', $key->get('kid')) : 'the first key';

        return sprintf('%s: %s', $kid, $selector->problems($key, $algorithm)[0] ?? 'does not fit');
    }

    /**
     * @param  list<SigningAlgorithm>  $algorithms
     */
    private function algorithms(array $algorithms): string
    {
        return implode(', ', array_map(static fn (SigningAlgorithm $algorithm): string => $algorithm->value, $algorithms));
    }

    private function localHost(string $host): bool
    {
        return in_array(strtolower($host), ['localhost', '127.0.0.1', '[::1]'], true)
            || str_ends_with(strtolower($host), '.localhost')
            || str_ends_with(strtolower($host), '.test');
    }
}

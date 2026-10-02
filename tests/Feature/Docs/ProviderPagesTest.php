<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\DocEnvironment;
use Cbox\Oidc\Tests\Support\DocExamples;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Illuminate\Http\RedirectResponse;

/**
 * Every page of docs/providers signs a person in, against an in-process
 * provider with that provider's issuer, discovery URL and client
 * registration, and passes oidc:check's diagnosis. Each page's .env goes
 * into the environment, the published config/oidc.php is read under it, and
 * the page's keys for connections.main are added, as an application does.
 */
afterEach(function (): void {
    DocEnvironment::restore();
});

/**
 * Loads a page's .env, and its keys for connections.main when it has some,
 * and returns the provider it describes, installed.
 */
function providerPage(string $env, ?string $config = null): FakeProvider
{
    test()->fakeSsrfDns([
        'accounts.google.com' => ['142.250.74.45'],
        'login.microsoftonline.com' => ['20.190.160.1'],
        'example.okta.com' => ['3.33.152.147'],
        'sso.example.com' => ['93.184.216.34'],
        'example-tenant.eu.auth0.com' => ['104.18.32.68'],
        'id.example.com' => ['93.184.216.35'],
    ]);

    DocEnvironment::use(DocExamples::code($env));

    if ($config !== null) {
        $keys = DocExamples::run($config);
        expect($keys)->toBeArray();
        Refusals::useConnection('main', array_replace((array) config('oidc.connections.main'), (array) $keys));
    }

    $connection = resolve(OidcConfig::class)->connection();
    $issuer = $connection->issuer;
    $base = $connection->hasTenantTemplate()
        ? 'https://login.microsoftonline.com/organizations/oauth2/v2.0'
        : rtrim($issuer, '/').'/oauth';

    $provider = new FakeProvider($issuer, $connection->discoveryUrl, $base);
    $provider->clients = [$connection->clientId => $connection->clientSecret === null ? ['public' => true] : ['secret' => $connection->clientSecret]];
    $provider->discovery['id_token_signing_alg_values_supported'] = ['RS256'];

    if ($connection->hasTenantTemplate()) {
        $provider->keys = [FakeProvider::rsaKey('entra-1', values: ['issuer' => $issuer])];
    }

    return $provider->install();
}

dataset('provider pages', [
    'google' => ['provider-google', null, [], null, []],
    'google, Workspace domains' => ['provider-google', 'provider-google-workspace', ['hd' => 'example.com'], 'example.com', []],
    'entra, one tenant' => ['provider-entra-single', 'provider-entra-single-config', ['tid' => '3f2504e0-4f89-41d3-9a0c-0305e82c3301'], '3f2504e0-4f89-41d3-9a0c-0305e82c3301', []],
    'entra, several tenants' => ['provider-entra-multi', 'provider-entra-multi-config', ['tid' => '22222222-2222-2222-2222-222222222222'], '22222222-2222-2222-2222-222222222222', []],
    'okta' => ['provider-okta', 'provider-okta-config', ['groups' => ['Everyone', 'Staff']], null, ['Everyone', 'Staff']],
    'keycloak' => ['provider-keycloak', 'provider-keycloak-config', ['groups' => ['staff']], null, ['staff']],
    'auth0' => ['provider-auth0', 'provider-auth0-config', ['https://app.example.com/roles' => ['editor']], null, ['editor']],
    'cbox id' => ['provider-cbox-id', 'provider-cbox-id-config', [], null, []],
]);

it('signs in through the documented settings', function (string $env, ?string $config, array $claims, ?string $tenant, array $groups): void {
    $this->freezeSecond();
    $provider = providerPage($env, $config);

    $request = Oidc::start();
    $result = Oidc::callback(request: ConnectionFixtures::callbackRequest($provider->approve($request->url, [...$claims, 'sub' => 'person-1'])));

    expect($result->connection)->toBe('main')
        ->and($result->claims->subject)->toBe('person-1')
        ->and($result->claims->tenant)->toBe($tenant)
        ->and($result->claims->groups)->toBe($groups)
        ->and(resolve(ConnectionDiagnostics::class)->diagnose()->passed())->toBeTrue();
})->with('provider pages');

it('refuses a personal Google account once the Workspace domain is pinned', function (): void {
    $this->freezeSecond();
    $provider = providerPage('provider-google', 'provider-google-workspace');
    $request = Oidc::start();

    expect(fn () => Oidc::callback(request: ConnectionFixtures::callbackRequest($provider->approve($request->url))))
        ->toThrow(TenantRejected::class, '[oidc_tenant_claim_missing]');
});

it('asks Google for a refresh token, and for consent on one login only', function (): void {
    providerPage('provider-google', 'provider-google-refresh');

    parse_str((string) parse_url(Oidc::start()->url, PHP_URL_QUERY), $plain);
    $redirect = DocExamples::run('provider-google-consent');
    expect($redirect)->toBeInstanceOf(RedirectResponse::class);
    parse_str((string) parse_url($redirect->getTargetUrl(), PHP_URL_QUERY), $consent);

    expect($plain)->toMatchArray(['access_type' => 'offline'])
        ->and($plain)->not->toHaveKey('prompt')
        ->and($consent)->toMatchArray(['access_type' => 'offline', 'prompt' => 'consent']);
});

it('publishes no fallback values, so an unset variable fails as invalid configuration', function (): void {
    foreach (DocExamples::blocks() as $block) {
        if (str_starts_with($block['file'], 'docs/providers/') && $block['language'] === 'php') {
            expect($block['code'])->not->toContain('env(');
        }
    }

    DocEnvironment::use("OIDC_ISSUER=https://accounts.google.com\nOIDC_REDIRECT_URI=https://app.example.com/oidc/callback");

    expect(fn () => resolve(OidcConfig::class))->toThrow(InvalidConfiguration::class, 'oidc.connections.main.client_secret is required for client_auth client_secret_basic');
});

it('covers every provider page', function (): void {
    $names = array_values(array_filter(array_unique(array_column(DocExamples::blocks(), 'name')), static fn (?string $name): bool => $name !== null && str_starts_with($name, 'provider-')));
    sort($names);

    expect($names)->toBe([
        'provider-auth0', 'provider-auth0-config', 'provider-cbox-id', 'provider-cbox-id-config',
        'provider-entra-multi', 'provider-entra-multi-config', 'provider-entra-single', 'provider-entra-single-config',
        'provider-google', 'provider-google-consent', 'provider-google-refresh', 'provider-google-workspace',
        'provider-keycloak', 'provider-keycloak-config', 'provider-okta', 'provider-okta-config',
    ]);
});

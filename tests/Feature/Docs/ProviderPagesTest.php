<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Tests\Support\DocExamples;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Http\Request;

/**
 * Every configuration of docs/providers signs a person in, against an
 * in-process provider with that provider's issuer, discovery URL, algorithms
 * and client registration, and passes oidc:check's diagnosis.
 */
dataset('provider pages', [
    'google' => ['provider-google', ['hd' => 'example.com'], 'example.com'],
    'entra, one tenant' => ['provider-entra-single', ['tid' => '3f2504e0-4f89-41d3-9a0c-0305e82c3301'], '3f2504e0-4f89-41d3-9a0c-0305e82c3301'],
    'entra, several tenants' => ['provider-entra-multi', ['tid' => '22222222-2222-2222-2222-222222222222'], '22222222-2222-2222-2222-222222222222'],
    'okta' => ['provider-okta', ['groups' => ['Everyone', 'Staff']], null],
    'keycloak' => ['provider-keycloak', ['groups' => ['staff']], null],
    'auth0' => ['provider-auth0', ['https://app.example.com/roles' => ['editor']], null],
    'cbox id' => ['provider-cbox-id', [], null],
]);

it('signs in through the documented configuration', function (string $example, array $claims, ?string $tenant): void {
    $this->fakeSsrfDns([
        'accounts.google.com' => ['142.250.74.45'],
        'login.microsoftonline.com' => ['20.190.160.1'],
        'example.okta.com' => ['3.33.152.147'],
        'sso.example.com' => ['93.184.216.34'],
        'example-tenant.eu.auth0.com' => ['104.18.32.68'],
        'id.example.com' => ['93.184.216.35'],
    ]);

    $config = DocExamples::run($example);
    expect($config)->toBeArray();
    config(['oidc.default' => $config['default'], 'oidc.connections' => $config['connections']]);

    $connection = resolve(OidcConfig::class)->connection();
    $issuer = $connection->issuer;
    $base = $connection->hasTenantTemplate()
        ? 'https://login.microsoftonline.com/organizations/oauth2/v2.0'
        : rtrim($issuer, '/').'/oauth';

    $provider = new FakeProvider($issuer, $connection->discoveryUrl, $base);
    $provider->clients = [$connection->clientId => $connection->clientSecret === null ? ['public' => true] : ['secret' => $connection->clientSecret]];
    $provider->discovery['id_token_signing_alg_values_supported'] = array_map(static fn ($algorithm): string => $algorithm->value, $connection->algorithms);

    if ($connection->hasTenantTemplate()) {
        $provider->keys = [FakeProvider::rsaKey('entra-1', values: ['issuer' => $issuer])];
    }

    $provider->install();

    $request = Oidc::start();
    $result = Oidc::callback(request: Request::create($connection->redirectUri, 'GET', $provider->approve($request->url, [...$claims, 'sub' => 'person-1'])));

    expect($result->connection)->toBe($connection->name)
        ->and($result->claims->subject)->toBe('person-1')
        ->and($result->claims->tenant)->toBe($tenant)
        ->and($result->claims->groups)->toBe($connection->groups->source->value === 'none' ? null : ($claims[$connection->groups->claim] ?? []));

    $diagnosis = resolve(ConnectionDiagnostics::class)->diagnose();

    expect($diagnosis->passed())->toBeTrue();
})->with('provider pages');

it('covers every provider page', function (): void {
    $names = array_values(array_filter(array_unique(array_column(DocExamples::blocks(), 'name')), static fn (?string $name): bool => $name !== null && str_starts_with($name, 'provider-')));
    sort($names);

    expect($names)->toBe(['provider-auth0', 'provider-cbox-id', 'provider-entra-multi', 'provider-entra-single', 'provider-google', 'provider-keycloak', 'provider-okta']);
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\DocEnvironment;
use Cbox\Oidc\Tests\Support\DocExamples;
use Cbox\Oidc\Tests\Support\FakeProvider;

/**
 * The local Keycloak .env of docs/providers/keycloak.md signs a person in
 * against a provider on http://127.0.0.1:8080, through the published
 * config/oidc.php.
 */
afterEach(function (): void {
    DocEnvironment::restore();
});

it('signs in to a local Keycloak with the documented .env', function (): void {
    $this->freezeSecond();
    DocEnvironment::use(DocExamples::code('keycloak-local-env'));

    $keycloak = new FakeProvider('http://127.0.0.1:8080/realms/dev', endpoints: 'http://127.0.0.1:8080/realms/dev/protocol/openid-connect');
    $keycloak->clients = ['my-app' => ['secret' => 'secret-from-the-credentials-tab']];
    $keycloak->install();

    $request = Oidc::start();
    $result = Oidc::callback(request: ConnectionFixtures::callbackRequest($keycloak->approve($request->url, ['sub' => 'dev-1'])));

    expect($result->claims->issuer)->toBe('http://127.0.0.1:8080/realms/dev')
        ->and($result->claims->subject)->toBe('dev-1')
        ->and(resolve(ConnectionDiagnostics::class)->diagnose()->passed())->toBeTrue();
});

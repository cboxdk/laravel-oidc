<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Diagnostics\Finding;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Support\Facades\Http;

/**
 * A provider on the developer's own machine, such as Keycloak in Docker on
 * http://127.0.0.1:8080, with allow_insecure_http and the SSRF guard's
 * enforcement off, as docs/providers/keycloak.md describes.
 */
beforeEach(function (): void {
    $this->freezeSecond();
    config(['ssrf.enforce' => false]);
    $this->keycloak = new FakeProvider('http://127.0.0.1:8080/realms/dev', endpoints: 'http://127.0.0.1:8080/realms/dev/protocol/openid-connect')->install();
    $this->useKeycloak = function (array $overrides = []): void {
        Refusals::useConnection('main', ConnectionFixtures::minimal([
            'issuer' => 'http://127.0.0.1:8080/realms/dev',
            'allow_insecure_http' => true,
            'redirect_uri' => 'http://127.0.0.1:8000/oidc/callback',
            ...$overrides,
        ]));
    };
});

it('signs in through a provider on http://127.0.0.1 in a local environment', function (): void {
    ($this->useKeycloak)();
    $flow = resolve(AuthorizationFlow::class);

    $request = $flow->start();
    $result = $flow->callback(ConnectionFixtures::callbackRequest($this->keycloak->approve($request->url, ['sub' => 'dev-1'])));

    expect($request->url)->toStartWith('http://127.0.0.1:8080/realms/dev/protocol/openid-connect/authorize?')
        ->and($result->claims->issuer)->toBe('http://127.0.0.1:8080/realms/dev')
        ->and($result->claims->subject)->toBe('dev-1');

    Http::assertSent(fn (ClientRequest $sent): bool => $sent->url() === 'http://127.0.0.1:8080/realms/dev/protocol/openid-connect/token');
});

it('accepts it with a string from the environment', function (): void {
    ($this->useKeycloak)(['allow_insecure_http' => 'true']);

    expect(resolve(OidcConfig::class)->connection()->allowInsecureHttp)->toBeTrue()
        ->and(resolve(OidcConfig::class)->http->allowInsecureHttp)->toBeTrue();
});

it('warns in oidc:check', function (): void {
    ($this->useKeycloak)();

    $diagnosis = resolve(ConnectionDiagnostics::class)->diagnose();

    expect($diagnosis->passed())->toBeTrue()
        ->and(array_map(static fn (Finding $finding): string => $finding->status->value.' '.$finding->check, $diagnosis->findings))->toContain('warn insecure http');
});

it('refuses allow_insecure_http outside a local or testing environment', function (): void {
    app()['env'] = 'production';
    ($this->useKeycloak)();

    try {
        resolve(OidcConfig::class);
    } catch (InvalidConfiguration $exception) {
        expect($exception->key())->toBe('oidc.connections.main.allow_insecure_http')
            ->and($exception->getMessage())->toContain('is only accepted when APP_ENV is local or testing');

        return;
    }

    test()->fail('allow_insecure_http was accepted in production.');
});

it('refuses an http issuer without allow_insecure_http', function (): void {
    ($this->useKeycloak)(['allow_insecure_http' => false]);

    expect(fn () => resolve(OidcConfig::class))->toThrow(InvalidConfiguration::class, 'oidc.connections.main.issuer must be an absolute https URL');
});

it('keeps http endpoints out of a connection without it', function (): void {
    $provider = new FakeProvider()->install();
    $provider->discovery['token_endpoint'] = 'http://idp.example.test/oauth/token';
    ($this->useKeycloak)(['allow_insecure_http' => 'false', 'issuer' => FakeProvider::ISSUER]);

    expect(fn () => resolve(AuthorizationFlow::class)->start())->toThrow(DiscoveryFailed::class, 'has token_endpoint set to something other than an https URL');
});

it('keeps the client on https while no connection allows http', function (): void {
    expect(resolve(OidcConfig::class)->http->allowInsecureHttp)->toBeFalse();

    config(['oidc.connections.main.discovery_url' => 'https://idp.example.test/.well-known/openid-configuration']);
    Http::fake(['http://plain.example.test/*' => Http::response('{}')]);

    expect(fn () => resolve(HttpClient::class)->send(HttpRequest::get('http://plain.example.test/doc')))
        ->toThrow(OutboundRequestBlocked::class);
});

it('reads only true or false', function (): void {
    ($this->useKeycloak)(['allow_insecure_http' => 'yes']);

    expect(fn () => resolve(OidcConfig::class))->toThrow(InvalidConfiguration::class, 'oidc.connections.main.allow_insecure_http must be true or false');
});

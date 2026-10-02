<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Diagnostics\CheckStatus;
use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Support\Facades\Artisan;

beforeEach(function (): void {
    $this->provider = new FakeProvider()->install();
    $this->json = function (array $arguments = []): array {
        $code = Artisan::call('oidc:check', [...$arguments, '--json' => true]);
        $document = json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);

        return [$code, $document];
    };
    $this->statuses = fn (array $connection): array => array_map(
        static fn (array $finding): string => $finding['status'].' '.$finding['check'],
        $connection['findings'],
    );
});

it('reports a healthy connection and exits 0', function (): void {
    $this->artisan('oidc:check')
        ->expectsOutputToContain('PASS  configuration  Issuer https://idp.example.test, client client-1, client_auth client_secret_basic.')
        ->expectsOutputToContain('PASS  discovery      https://idp.example.test/.well-known/openid-configuration names the pinned issuer https://idp.example.test.')
        ->expectsOutputToContain('PASS  keys           3 of the 3 keys at https://idp.example.test/oauth/jwks may verify ID tokens.')
        ->expectsOutputToContain('PASS  back-channel   The provider announces back-channel logout, with sid.')
        ->expectsOutputToContain('Connection main can sign people in.')
        ->assertExitCode(0);
});

it('prints JSON', function (): void {
    [$code, $document] = ($this->json)();

    expect($code)->toBe(0)
        ->and($document['connections'])->toHaveCount(1)
        ->and($document['connections'][0]['connection'])->toBe('main')
        ->and($document['connections'][0]['passed'])->toBeTrue()
        ->and(($this->statuses)($document['connections'][0]))->toBe([
            'pass configuration',
            'pass discovery',
            'pass algorithms',
            'pass keys',
            'pass userinfo',
            'pass logout',
            'pass revocation',
            'pass back-channel',
            'pass iss parameter',
        ])
        ->and($document['connections'][0]['findings'][2])->toBe([
            'status' => 'pass',
            'check' => 'algorithms',
            'message' => 'ID tokens may be signed with RS256, ES256, EdDSA.',
            'fix' => null,
            'code' => null,
        ]);
});

it('fetches the documents afresh instead of trusting the cache', function (): void {
    resolve(MetadataRepository::class)->for(resolve(OidcConfig::class)->connection());

    $this->artisan('oidc:check')->assertExitCode(0);

    expect($this->provider->discoveryRequests)->toBe(2)
        ->and($this->provider->jwksRequests)->toBe(1);
});

it('fails with the error code and fix of a discovery document for another issuer', function (): void {
    $this->provider->discovery['issuer'] = 'https://idp.example.test/';

    $this->artisan('oidc:check')
        ->expectsOutputToContain('FAIL  discovery')
        ->expectsOutputToContain('[oidc_discovery_issuer_mismatch] Fix: If "https://idp.example.test/" is the provider you mean, set oidc.connections.main.issuer to it exactly')
        ->expectsOutputToContain('Connection main cannot sign people in: 1 check(s) failed.')
        ->assertExitCode(1);

    expect($this->provider->jwksRequests)->toBe(0);
});

it('fails when no key can verify the algorithms the connection accepts', function (): void {
    config(['oidc.connections.main.algorithms' => ['RS256']]);
    $this->provider->keys = [FakeProvider::ecKey('ec-1')];

    [$code, $document] = ($this->json)();
    $keys = $document['connections'][0]['findings'][3];

    expect($code)->toBe(1)
        ->and($keys['status'])->toBe('fail')
        ->and($keys['code'])->toBe('oidc_signing_key_not_found')
        ->and($keys['message'])->toBe('None of the 1 keys at https://idp.example.test/oauth/jwks may verify a token signed with RS256: key "ec-1": it is a EC key, and RS256 takes RSA.')
        ->and($keys['fix'])->toContain('oidc.connections.main.algorithms');
});

it('fails on an empty key set, and on one that is not a key set', function (): void {
    $this->provider->keys = [];

    [$code, $document] = ($this->json)();

    expect($code)->toBe(1)
        ->and($document['connections'][0]['findings'][3]['message'])->toBe('The key set at https://idp.example.test/oauth/jwks has no key the package can read.');

    $this->provider->jwksBody = '{"nokeys": true}';
    [, $document] = ($this->json)();

    expect($document['connections'][0]['findings'][3]['code'])->toBe('oidc_jwks_invalid');
});

it('warns about usable keys without a kid', function (): void {
    $this->provider->keys = [FakeProvider::rsaKey('a'), FakeProvider::rsaKey('b')];
    $this->provider->jwksBody = json_encode(['keys' => array_map(
        static fn (array $key): array => array_diff_key($key, ['kid' => true]),
        $this->provider->jwks()['keys'],
    )], JSON_THROW_ON_ERROR);

    [$code, $document] = ($this->json)();

    expect($code)->toBe(0)
        ->and(($this->statuses)($document['connections'][0]))->toContain('warn keys');
});

it('fails when groups come from userinfo and the provider has none', function (): void {
    config(['oidc.connections.main.groups' => ['source' => 'userinfo']]);
    unset($this->provider->discovery['userinfo_endpoint']);

    $this->artisan('oidc:check')
        ->expectsOutputToContain('FAIL  userinfo       The provider has no userinfo_endpoint, and the connection reads its groups from userinfo')
        ->expectsOutputToContain('[oidc_endpoint_not_supported] Fix: Set oidc.connections.main.groups.source to id_token or none.')
        ->assertExitCode(1);
});

it('notes the optional endpoints a provider lacks', function (): void {
    foreach (['userinfo_endpoint', 'end_session_endpoint', 'revocation_endpoint', 'backchannel_logout_supported', 'authorization_response_iss_parameter_supported'] as $member) {
        unset($this->provider->discovery[$member]);
    }

    [$code, $document] = ($this->json)();

    expect($code)->toBe(0)
        ->and(array_slice(($this->statuses)($document['connections'][0]), 4))->toBe([
            'note userinfo',
            'note logout',
            'note revocation',
            'note back-channel',
            'note iss parameter',
        ]);
});

it('warns about an http redirect URI on a public host and a tenant policy that accepts anyone', function (): void {
    config(['oidc.connections.main' => ConnectionFixtures::minimal([
        'redirect_uri' => 'http://app.example.com/oidc/callback',
        'tenant' => ['claim' => 'org', 'allowed' => ['*']],
    ])]);

    $this->artisan('oidc:check')
        ->expectsOutputToContain('WARN  redirect_uri   http://app.example.com/oidc/callback uses http on a host that is not local')
        ->expectsOutputToContain('WARN  tenant         Any value of the org claim is accepted')
        ->expectsOutputToContain('Connection main can sign people in, with 2 warning(s).')
        ->assertExitCode(0);
});

it('accepts http on local hosts, and reports a pinned tenant', function (): void {
    config(['oidc.connections.main' => ConnectionFixtures::minimal([
        'redirect_uri' => 'http://localhost:8000/oidc/callback',
        'tenant' => ['claim' => 'org', 'allowed' => ['acme']],
    ])]);

    [, $document] = ($this->json)();

    expect(($this->statuses)($document['connections'][0]))->toContain('pass tenant')
        ->and(($this->statuses)($document['connections'][0]))->not->toContain('warn redirect_uri');
});

it('fails on a connection that is not configured', function (): void {
    $this->artisan('oidc:check', ['connection' => 'nope'])
        ->expectsOutputToContain('Connection nope')
        ->expectsOutputToContain('FAIL  configuration  There is no OIDC connection named "nope".')
        ->expectsOutputToContain('[oidc_connection_unknown] Fix: Use one of main, workspace, or add it under connections in config/oidc.php.')
        ->assertExitCode(1);
});

it('fails on an invalid configuration', function (): void {
    config(['oidc.connections.main.issuer' => 'http://idp.example.test']);

    $this->artisan('oidc:check', ['--all' => true])
        ->expectsOutputToContain('Connection default')
        ->expectsOutputToContain('[oidc_config_invalid]')
        ->assertExitCode(1);
});

it('checks every connection with --all', function (): void {
    $google = new FakeProvider('https://accounts.google.com')->install();
    $google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];
    unset($google->discovery['end_session_endpoint']);

    [$code, $document] = ($this->json)(['--all' => true]);

    expect($code)->toBe(0)
        ->and(array_column($document['connections'], 'connection'))->toBe(['main', 'workspace'])
        ->and(($this->statuses)($document['connections'][1]))->toContain('pass tenant', 'note logout');
});

it('fails --all when one connection fails', function (): void {
    $google = new FakeProvider('https://accounts.google.com')->install();
    $google->discoveryStatus = 404;

    [$code, $document] = ($this->json)(['--all' => true]);

    expect($code)->toBe(1)
        ->and($document['connections'][0]['passed'])->toBeTrue()
        ->and($document['connections'][1]['passed'])->toBeFalse()
        ->and(array_column($document['connections'][1]['findings'], 'code', 'check'))->toBe(['configuration' => null, 'tenant' => null, 'discovery' => 'oidc_provider_response_invalid']);
});

it('prints provider text as text, not as console markup', function (): void {
    $this->provider->discovery['issuer'] = 'https://idp.example.test/<fg=red>';

    $this->artisan('oidc:check')
        ->expectsOutputToContain('names the issuer "https://idp.example.test/<fg=red>"')
        ->assertExitCode(1);
});

it('counts findings by status', function (): void {
    $diagnosis = resolve(ConnectionDiagnostics::class)->diagnose();

    expect($diagnosis->passed())->toBeTrue()
        ->and($diagnosis->count(CheckStatus::Pass))->toBe(9)
        ->and($diagnosis->count(CheckStatus::Fail))->toBe(0)
        ->and($diagnosis->toArray()['connection'])->toBe('main');
});

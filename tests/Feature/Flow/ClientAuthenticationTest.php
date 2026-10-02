<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Flow\CallbackResult;
use Cbox\Oidc\Tests\Support\ClientKeys;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Http\Request;
use Jose\Component\Signature\Serializer\CompactSerializer;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->login = function (array $connection): CallbackResult {
        config(['oidc.connections.main' => ConnectionFixtures::minimal($connection)]);
        app()->forgetInstance(OidcConfig::class);
        app()->forgetInstance(AuthorizationFlow::class);
        $flow = resolve(AuthorizationFlow::class);

        return $flow->callback(Request::create('/oidc/callback', 'GET', $this->provider->approve($flow->start()->url)));
    };
});

it('sends the secret with HTTP Basic, form-encoded first (RFC 6749 2.3.1)', function (): void {
    $this->provider->clients = ['client:1 ä' => ['secret' => 's3cr%t+/=']];

    ($this->login)(['client_id' => 'client:1 ä', 'client_secret' => 's3cr%t+/=']);

    expect($this->provider->tokenRequests[0]['authorization'])->toBe('Basic '.base64_encode('client%3A1+%C3%A4:s3cr%25t%2B%2F%3D'))
        ->and($this->provider->tokenRequests[0]['form'])->not->toHaveKeys(['client_id', 'client_secret']);
});

it('sends the secret in the form with client_secret_post', function (): void {
    ($this->login)(['client_auth' => 'client_secret_post']);

    expect($this->provider->tokenRequests[0]['authorization'])->toBeNull()
        ->and($this->provider->tokenRequests[0]['form'])->toMatchArray(['client_id' => 'client-1', 'client_secret' => 'secret-1']);
});

it('sends only the client id for a public client', function (): void {
    $this->provider->clients['public-1'] = ['public' => true];

    ($this->login)(['client_id' => 'public-1', 'client_auth' => 'none', 'client_secret' => null]);

    expect($this->provider->tokenRequests[0]['authorization'])->toBeNull()
        ->and($this->provider->tokenRequests[0]['form'])->toHaveKey('client_id', 'public-1')
        ->and($this->provider->tokenRequests[0]['form'])->toHaveKey('code_verifier')
        ->and($this->provider->tokenRequests[0]['form'])->not->toHaveKey('client_secret');
});

it('signs a client assertion with private_key_jwt', function (string $keyType, string $algorithm): void {
    $pem = match ($keyType) {
        'ec' => ClientKeys::ec(),
        'ed25519' => ClientKeys::ed25519(),
        default => ClientKeys::rsa(),
    };
    $this->provider->clients['client-1'] = ['public_key' => ClientKeys::publicJwk($pem)];

    ($this->login)([
        'client_auth' => 'private_key_jwt',
        'client_secret' => null,
        'client_assertion' => ['key' => $pem, 'algorithm' => $algorithm, 'key_id' => 'client-key-1'],
    ]);

    $form = $this->provider->tokenRequests[0]['form'];
    $header = new CompactSerializer()->unserialize((string) $form['client_assertion'])->getSignature(0)->getProtectedHeader();

    expect($this->provider->tokenRequests[0]['authorization'])->toBeNull()
        ->and($form)->toMatchArray(['client_id' => 'client-1', 'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'])
        ->and($form)->not->toHaveKey('client_secret')
        ->and($header)->toBe(['alg' => $algorithm, 'typ' => 'JWT', 'kid' => 'client-key-1'])
        ->and($this->provider->lastAssertion)->toMatchArray([
            'iss' => 'client-1',
            'sub' => 'client-1',
            'aud' => FakeProvider::TOKEN_URL,
            'iat' => now()->getTimestamp(),
            'nbf' => now()->getTimestamp(),
            'exp' => now()->getTimestamp() + 60,
        ])
        ->and($this->provider->lastAssertion['jti'] ?? null)->toMatch('/^[A-Za-z0-9_-]{43}$/');
})->with([
    'RS256' => ['rsa', 'RS256'],
    'PS256' => ['rsa', 'PS256'],
    'ES256' => ['ec', 'ES256'],
    'EdDSA' => ['ed25519', 'EdDSA'],
]);

it('names the issuer as audience and adds extra header members when asked', function (): void {
    $this->provider->clients['client-1'] = ['public_key' => ClientKeys::publicJwk(ClientKeys::rsa())];
    $this->provider->assertionAudience = FakeProvider::ISSUER;

    ($this->login)([
        'client_auth' => 'private_key_jwt',
        'client_secret' => null,
        'client_assertion' => ['key' => ClientKeys::rsa(), 'audience' => 'issuer', 'headers' => ['x5t#S256' => 'thumbprint'], 'lifetime_seconds' => 30],
    ]);

    $assertion = (string) $this->provider->tokenRequests[0]['form']['client_assertion'];

    expect(new CompactSerializer()->unserialize($assertion)->getSignature(0)->getProtectedHeader())->toBe(['alg' => 'RS256', 'typ' => 'JWT', 'x5t#S256' => 'thumbprint'])
        ->and($this->provider->lastAssertion)->toMatchArray(['aud' => FakeProvider::ISSUER, 'exp' => now()->getTimestamp() + 30]);
});

it('makes a fresh assertion for every request', function (): void {
    $this->provider->clients['client-1'] = ['public_key' => ClientKeys::publicJwk(ClientKeys::rsa())];
    $connection = ['client_auth' => 'private_key_jwt', 'client_secret' => null, 'client_assertion' => ['key' => ClientKeys::rsa()]];

    ($this->login)($connection);
    $first = $this->provider->lastAssertion['jti'] ?? null;
    ($this->login)($connection);

    expect($this->provider->lastAssertion['jti'] ?? null)->not->toBe($first);
});

it('refuses private_key_jwt with a provider that does not list it', function (): void {
    $this->provider->discovery['token_endpoint_auth_methods_supported'] = ['client_secret_basic'];

    expect(fn (): CallbackResult => ($this->login)(['client_auth' => 'private_key_jwt', 'client_secret' => null, 'client_assertion' => ['key' => ClientKeys::rsa()]]))
        ->toThrow(DiscoveryFailed::class, 'does not support client_auth private_key_jwt');
});

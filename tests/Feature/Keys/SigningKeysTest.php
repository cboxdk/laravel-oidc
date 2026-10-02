<?php

declare(strict_types=1);

use Cbox\Oidc\Cache\DocumentCache;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\KeySetInvalid;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\SigningKeyNotFound;
use Cbox\Oidc\Exceptions\SigningKeyUnsuitable;
use Cbox\Oidc\Keys\KeySetRepository;
use Cbox\Oidc\Keys\SigningKeys;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->find = fn (SigningAlgorithm $algorithm, ?string $kid): JWK => resolve(SigningKeys::class)->find(resolve(OidcConfig::class)->connection(), $algorithm, $kid);
});

it('finds the provider key for RS256, ES256 and EdDSA and verifies with it', function (SigningAlgorithm $algorithm, string $kid): void {
    $token = $this->provider->sign(['iss' => FakeProvider::ISSUER, 'sub' => 'alice'], $algorithm);
    $key = ($this->find)($algorithm, $kid);
    $verifier = new JWSVerifier(new AlgorithmManager([$algorithm->signatureAlgorithm()]));

    expect($key->get('kid'))->toBe($kid)
        ->and($key->has('d'))->toBeFalse()
        ->and($verifier->verifyWithKey(new CompactSerializer()->unserialize($token), $key, 0))->toBeTrue();
})->with([
    'RS256' => [SigningAlgorithm::RS256, 'rsa-1'],
    'ES256' => [SigningAlgorithm::ES256, 'ec-1'],
    'EdDSA' => [SigningAlgorithm::EdDSA, 'ed-1'],
]);

it('fetches the key set from jwks_uri once and caches it', function (): void {
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    ($this->find)(SigningAlgorithm::ES256, 'ec-1');

    expect($this->provider->jwksRequests)->toBe(1)
        ->and($this->provider->discoveryRequests)->toBe(1);
    Http::assertSent(fn (Request $request): bool => $request->url() === FakeProvider::JWKS_URL && str_contains($request->header('Accept')[0] ?? '', 'application/jwk-set+json'));
});

it('keeps the key set for the provider\'s max-age, clamped to the configured bounds', function (?string $cacheControl, int $lifetime): void {
    config(['oidc.cache.jwks_default_ttl_seconds' => 1800, 'oidc.cache.jwks_min_ttl_seconds' => 300, 'oidc.cache.jwks_max_ttl_seconds' => 7200]);
    $this->provider->jwksCacheControl = $cacheControl;

    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    $this->travel($lifetime - 1)->seconds();
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');

    expect($this->provider->jwksRequests)->toBe(1);

    $this->travel(1)->seconds();
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');

    expect($this->provider->jwksRequests)->toBe(2);
})->with([
    'max-age within bounds' => ['public, max-age=600', 600],
    'max-age below the minimum' => ['max-age=5', 300],
    'max-age above the maximum' => ['max-age=604800', 7200],
    'no-store' => ['no-store', 300],
    'no Cache-Control' => [null, 1800],
]);

it('refetches once on an unknown kid and finds a rotated key', function (): void {
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    $this->provider->keys[] = FakeProvider::rsaKey('rsa-2');

    $key = ($this->find)(SigningAlgorithm::RS256, 'rsa-2');

    expect($key->get('kid'))->toBe('rsa-2')
        ->and($this->provider->jwksRequests)->toBe(2);
});

it('refetches when a token without kid finds no key, after a rotation to a new key type', function (): void {
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    $this->provider->keys = [FakeProvider::ecKey('ec-2', 'P-384')];
    $this->provider->discovery['id_token_signing_alg_values_supported'] = ['ES384'];
    config(['oidc.connections.main.algorithms' => ['ES384']]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(MetadataRepository::class);
    app()->forgetInstance(SigningKeys::class);
    resolve(MetadataRepository::class)->forget(resolve(OidcConfig::class)->connection());

    expect(($this->find)(SigningAlgorithm::ES384, null)->get('kid'))->toBe('ec-2')
        ->and($this->provider->jwksRequests)->toBe(2);
});

it('does not refetch again within the cooldown', function (): void {
    config(['oidc.cache.jwks_refetch_cooldown_seconds' => 60]);
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'random-1'))
        ->toThrow(SigningKeyNotFound::class, 'has no key with kid "random-1" (also after refetching the key set).');
    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'random-2'))
        ->toThrow(SigningKeyNotFound::class, 'has no key with kid "random-2" (the key set was refetched within the cooldown, so it was not fetched again).');

    expect($this->provider->jwksRequests)->toBe(2);

    $this->travel(60)->seconds();

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'random-3'))->toThrow(SigningKeyNotFound::class);
    expect($this->provider->jwksRequests)->toBe(3);
});

it('uses a key set another process refetched instead of fetching again', function (): void {
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');

    // Another process: its own DocumentCache, the same store.
    $this->provider->keys[] = FakeProvider::rsaKey('rsa-2');
    $other = new DocumentCache(cache()->store(), resolve(ClockInterface::class));
    $repository = new KeySetRepository(resolve(HttpClient::class), $other, resolve(OidcConfig::class)->cache);
    $connection = resolve(OidcConfig::class)->connection();
    $repository->refresh($connection, resolve(MetadataRepository::class)->for($connection));

    expect($this->provider->jwksRequests)->toBe(2)
        ->and(($this->find)(SigningAlgorithm::RS256, 'rsa-2')->get('kid'))->toBe('rsa-2')
        ->and($this->provider->jwksRequests)->toBe(2);
});

it('does not refetch for a key that exists but does not fit', function (): void {
    $this->provider->keys[] = FakeProvider::rsaKey('weak', 1024);

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'weak'))
        ->toThrow(SigningKeyUnsuitable::class, 'The key "weak" of connection "main" may not verify a RS256 token: the key length is less than 2048 bits');
    expect(fn (): JWK => ($this->find)(SigningAlgorithm::ES256, 'rsa-1'))
        ->toThrow(SigningKeyUnsuitable::class, 'it is a RSA key, and ES256 takes EC');

    expect($this->provider->jwksRequests)->toBe(1);
});

it('does not refetch when a token without kid is ambiguous', function (): void {
    $this->provider->keys[] = FakeProvider::rsaKey('rsa-2');

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, null))->toThrow(SigningKeyNotFound::class, 'so the key is ambiguous');
    expect($this->provider->jwksRequests)->toBe(1);
});

it('reports an outage during a refetch as ProviderUnavailable', function (): void {
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    $this->provider->jwksStatus = 502;

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'rsa-2'))->toThrow(ProviderUnavailable::class, 'HTTP 502');
});

it('keeps using a stale key set while the provider is unavailable', function (): void {
    config(['oidc.cache.stale_if_error_seconds' => 600, 'oidc.cache.jwks_default_ttl_seconds' => 3600, 'oidc.cache.discovery_ttl_seconds' => 86400]);
    $this->provider->jwksCacheControl = null;
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    $this->provider->jwksStatus = 503;

    $this->travel(4199)->seconds();
    expect(($this->find)(SigningAlgorithm::RS256, 'rsa-1')->get('kid'))->toBe('rsa-1');

    $this->travel(1)->seconds();
    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'rsa-1'))->toThrow(ProviderUnavailable::class);
});

it('refuses what is not a key set, and does not cache it', function (?string $body, int $status, string $exception, string $message): void {
    $this->provider->jwksBody = $body;
    $this->provider->jwksStatus = $status;

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'rsa-1'))->toThrow($exception, $message);

    $this->provider->jwksBody = null;
    $this->provider->jwksStatus = 200;

    expect(($this->find)(SigningAlgorithm::RS256, 'rsa-1')->get('kid'))->toBe('rsa-1');
})->with([
    'an HTML page' => ['<html>error</html>', 200, InvalidProviderResponse::class, 'The key set from https://idp.example.test/oauth/jwks is not valid'],
    'no keys member' => ['{"issuer":"https://idp.example.test"}', 200, KeySetInvalid::class, 'has no "keys" list'],
    'duplicate keys member' => ['{"keys":[],"keys":[{"kty":"RSA"}]}', 200, InvalidProviderResponse::class, 'an object has the same key twice'],
    'too many keys' => [json_encode(['keys' => array_fill(0, 101, ['kty' => 'oct', 'k' => 'AA'])]), 200, KeySetInvalid::class, 'has 101 keys'],
    'not found' => [null, 404, InvalidProviderResponse::class, 'with HTTP 404'],
    'a server error' => [null, 500, ProviderUnavailable::class, 'with HTTP 500'],
]);

it('refuses a jwks_uri the SSRF guard blocks', function (): void {
    $this->provider->discovery['jwks_uri'] = 'https://metadata.example.test/keys';

    expect(fn (): JWK => ($this->find)(SigningAlgorithm::RS256, 'rsa-1'))->toThrow(OutboundRequestBlocked::class, 'https://metadata.example.test');
    expect($this->provider->jwksRequests)->toBe(0);
});

it('forgets the cached key set on request', function (): void {
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');
    $connection = resolve(OidcConfig::class)->connection();
    resolve(KeySetRepository::class)->forget($connection, resolve(MetadataRepository::class)->for($connection));
    ($this->find)(SigningAlgorithm::RS256, 'rsa-1');

    expect($this->provider->jwksRequests)->toBe(2);
});

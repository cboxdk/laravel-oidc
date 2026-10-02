<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\SigningKeyNotFound;
use Cbox\Oidc\Exceptions\SigningKeyUnsuitable;
use Cbox\Oidc\Keys\KeySelector;
use Cbox\Oidc\Keys\KeySet;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;

/**
 * @param  list<JWK>  $keys
 */
function keySet(array $keys): KeySet
{
    return new KeySet(array_map(static fn (JWK $key): JWK => $key->toPublic(), $keys));
}

it('selects the key a token names and the key verifies the token', function (SigningAlgorithm $algorithm, string $kid): void {
    $provider = new FakeProvider;
    $token = $provider->sign(['sub' => 'alice'], $algorithm);

    $key = new KeySelector()->select(keySet($provider->keys), $algorithm, $kid, 'main');
    $jws = new CompactSerializer()->unserialize($token);

    expect($key->get('kid'))->toBe($kid)
        ->and($key->has('d'))->toBeFalse()
        ->and(new JWSVerifier(new AlgorithmManager([$algorithm->signatureAlgorithm()]))->verifyWithKey($jws, $key, 0))->toBeTrue();
})->with([
    'RS256' => [SigningAlgorithm::RS256, 'rsa-1'],
    'ES256' => [SigningAlgorithm::ES256, 'ec-1'],
    'EdDSA' => [SigningAlgorithm::EdDSA, 'ed-1'],
]);

it('selects the only key that fits when the token names no kid', function (): void {
    $provider = new FakeProvider;

    expect(new KeySelector()->select(keySet($provider->keys), SigningAlgorithm::ES256, null, 'main')->get('kid'))->toBe('ec-1')
        ->and(new KeySelector()->select(keySet($provider->keys), SigningAlgorithm::PS256, null, 'main')->get('kid'))->toBe('rsa-1');
});

it('refuses an unknown kid, and says a refetch could help', function (): void {
    $selector = new KeySelector;

    expect(fn (): JWK => $selector->select(keySet(new FakeProvider()->keys), SigningAlgorithm::RS256, 'rotated', 'main'))
        ->toThrow(function (SigningKeyNotFound $exception): void {
            expect($exception->errorCode())->toBe(ErrorCode::SigningKeyNotFound)
                ->and($exception->refetchable())->toBeTrue()
                ->and($exception->getMessage())->toContain('The key set of connection "main" has no key with kid "rotated".');
        });
});

it('refuses a token without kid when no key fits', function (): void {
    expect(fn (): JWK => new KeySelector()->select(keySet([FakeProvider::rsaKey('rsa-1')]), SigningAlgorithm::ES256, null, 'main'))
        ->toThrow(function (SigningKeyNotFound $exception): void {
            expect($exception->refetchable())->toBeTrue()
                ->and($exception->getMessage())->toContain('has no key for ES256');
        });
});

it('never tries keys one by one when a token without kid fits several', function (): void {
    $keys = keySet([FakeProvider::rsaKey('rsa-1'), FakeProvider::rsaKey('rsa-2')]);

    expect(fn (): JWK => new KeySelector()->select($keys, SigningAlgorithm::RS256, null, 'main'))
        ->toThrow(function (SigningKeyNotFound $exception): void {
            expect($exception->refetchable())->toBeFalse()
                ->and($exception->getMessage())->toContain('has 2 keys for RS256, so the key is ambiguous');
        });
});

it('refuses two fitting keys under one kid', function (): void {
    $keys = keySet([FakeProvider::rsaKey('rsa-1'), FakeProvider::rsaKey('rsa-2', values: ['kid' => 'rsa-1'])]);

    expect(fn (): JWK => new KeySelector()->select($keys, SigningAlgorithm::RS256, 'rsa-1', 'main'))
        ->toThrow(SigningKeyNotFound::class, 'so the key is ambiguous');
});

it('picks the fitting key when one kid names keys of two types', function (): void {
    $keys = keySet([FakeProvider::rsaKey('rsa-1', values: ['kid' => 'shared']), FakeProvider::ecKey('ec-1', values: ['kid' => 'shared'])]);

    expect(new KeySelector()->select($keys, SigningAlgorithm::ES256, 'shared', 'main')->get('kty'))->toBe('EC');
});

it('refuses a named key that may not verify the token', function (JWK $key, SigningAlgorithm $algorithm, string $reason): void {
    expect(fn (): JWK => new KeySelector()->select(keySet([$key]), $algorithm, (string) $key->get('kid'), 'main'))
        ->toThrow(function (SigningKeyUnsuitable $exception) use ($reason): void {
            expect($exception->errorCode())->toBe(ErrorCode::SigningKeyUnsuitable)
                ->and($exception->getMessage())->toContain($reason);
        });
})->with([
    'an EC key under an RS256 header' => fn (): array => [FakeProvider::ecKey('k'), SigningAlgorithm::RS256, 'it is a EC key, and RS256 takes RSA'],
    'an RSA key under an ES256 header' => fn (): array => [FakeProvider::rsaKey('k'), SigningAlgorithm::ES256, 'it is a RSA key, and ES256 takes EC'],
    'an RSA key under an EdDSA header' => fn (): array => [FakeProvider::rsaKey('k'), SigningAlgorithm::EdDSA, 'it is a RSA key, and EdDSA takes OKP'],
    'an Ed25519 key under an ES256 header' => fn (): array => [FakeProvider::edKey('k'), SigningAlgorithm::ES256, 'it is a OKP key, and ES256 takes EC'],
    'a symmetric key' => fn (): array => [new JWK(['kty' => 'oct', 'kid' => 'k', 'k' => 'c2VjcmV0']), SigningAlgorithm::RS256, 'it is a oct key, and RS256 takes RSA'],
    'a P-384 key under an ES256 header' => fn (): array => [FakeProvider::ecKey('k', 'P-384'), SigningAlgorithm::ES256, 'its curve is not P-256'],
    'a P-256 key under an ES384 header' => fn (): array => [FakeProvider::ecKey('k'), SigningAlgorithm::ES384, 'its curve is not P-384'],
    'an X25519 key under an EdDSA header' => fn (): array => [new JWK(['kty' => 'OKP', 'crv' => 'X25519', 'kid' => 'k', 'x' => Base64UrlSafe::encodeUnpadded(random_bytes(32))]), SigningAlgorithm::EdDSA, 'its curve is not Ed25519'],
    'an encryption key' => fn (): array => [FakeProvider::rsaKey('k', values: ['use' => 'enc']), SigningAlgorithm::RS256, 'its use is not sig'],
    'key_ops without verify' => fn (): array => [FakeProvider::rsaKey('k', values: ['key_ops' => ['encrypt']]), SigningAlgorithm::RS256, 'its key_ops do not allow verify'],
    'key_ops that is not a list' => fn (): array => [FakeProvider::rsaKey('k', values: ['key_ops' => 'verify']), SigningAlgorithm::RS256, 'its key_ops do not allow verify'],
    'a key marked for another alg' => fn (): array => [FakeProvider::rsaKey('k', values: ['alg' => 'RS512']), SigningAlgorithm::RS256, 'it is marked for alg RS512'],
    'a key marked for HS256' => fn (): array => [FakeProvider::rsaKey('k', values: ['alg' => 'HS256']), SigningAlgorithm::RS256, 'it is marked for alg HS256'],
    'RSA 1024' => fn (): array => [FakeProvider::rsaKey('k', 1024), SigningAlgorithm::RS256, 'the key length is less than 2048 bits'],
    'RSA with exponent 3' => fn (): array => [FakeProvider::rsaKey('k', values: ['e' => 'Aw']), SigningAlgorithm::RS256, 'the exponent is too low'],
    'RSA without a modulus' => fn (): array => [new JWK(['kty' => 'RSA', 'kid' => 'k', 'e' => 'AQAB']), SigningAlgorithm::RS256, 'its key material is malformed'],
    'an EC point off the curve' => fn (): array => [FakeProvider::ecKey('k', values: ['y' => Base64UrlSafe::encodeUnpadded(str_repeat("\x01", 32))]), SigningAlgorithm::ES256, 'the point is not on the curve'],
    'an EC key with short coordinates' => fn (): array => [FakeProvider::ecKey('k', values: ['x' => 'AQ', 'y' => 'AQ']), SigningAlgorithm::ES256, 'size shall be 256 bits'],
    'an Ed25519 key with a short x' => fn (): array => [FakeProvider::edKey('k', ['x' => Base64UrlSafe::encodeUnpadded(random_bytes(16))]), SigningAlgorithm::EdDSA, 'its x is not a 32-byte Ed25519 public key'],
    'an Ed25519 key without x' => fn (): array => [new JWK(['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => 'k']), SigningAlgorithm::EdDSA, 'its x is not a 32-byte Ed25519 public key'],
    'an RSA modulus that is not base64url' => fn (): array => [FakeProvider::rsaKey('k', values: ['n' => '***']), SigningAlgorithm::RS256, 'its key material is malformed'],
]);

it('lists every reason a named key is refused', function (): void {
    $key = FakeProvider::rsaKey('k', 1024, ['use' => 'enc', 'alg' => 'RS512']);

    expect(fn (): JWK => new KeySelector()->select(keySet([$key]), SigningAlgorithm::RS256, 'k', 'main'))
        ->toThrow(SigningKeyUnsuitable::class, 'its use is not sig; it is marked for alg RS512; the key length is less than 2048 bits');
});

it('leaves unsuitable keys out when the token names no kid', function (): void {
    $keys = keySet([FakeProvider::rsaKey('weak', 1024), FakeProvider::rsaKey('enc', values: ['use' => 'enc']), FakeProvider::rsaKey('good')]);

    expect(new KeySelector()->select($keys, SigningAlgorithm::RS256, null, 'main')->get('kid'))->toBe('good');
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Config\AssertionAudience;
use Cbox\Oidc\Config\ClientAuthMethod;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Tests\Support\ClientKeys;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tokens\SigningAlgorithm;

/**
 * @param  array<string, mixed>  $assertion
 * @param  array<string, mixed>  $connection
 */
function keyJwtConnection(array $assertion, array $connection = []): ConnectionConfig
{
    return OidcConfig::fromArray(['connections' => ['main' => ConnectionFixtures::minimal([
        'client_auth' => 'private_key_jwt',
        'client_secret' => null,
        'client_assertion' => $assertion,
        ...$connection,
    ])]])->connection();
}

/**
 * @param  array<string, mixed>  $assertion
 * @param  array<string, mixed>  $connection
 */
function keyJwtRefusal(array $assertion, array $connection = []): InvalidConfiguration
{
    try {
        keyJwtConnection($assertion, $connection);
    } catch (InvalidConfiguration $exception) {
        return $exception;
    }

    throw new RuntimeException('The configuration was accepted.');
}

it('reads a private key from PEM text with the defaults', function (): void {
    $connection = keyJwtConnection(['key' => ClientKeys::rsa()]);

    expect($connection->clientAuth)->toBe(ClientAuthMethod::PrivateKeyJwt)
        ->and($connection->clientSecret)->toBeNull()
        ->and($connection->clientAssertion?->algorithm)->toBe(SigningAlgorithm::RS256)
        ->and($connection->clientAssertion?->audience)->toBe(AssertionAudience::TokenEndpoint)
        ->and($connection->clientAssertion?->keyId)->toBeNull()
        ->and($connection->clientAssertion?->headers)->toBe([])
        ->and($connection->clientAssertion?->lifetimeSeconds)->toBe(60)
        ->and($connection->clientAssertion?->key->get('kty'))->toBe('RSA')
        ->and($connection->clientAssertion?->key->has('d'))->toBeTrue();
});

it('reads a private key from a PEM file', function (): void {
    $file = (string) tempnam(sys_get_temp_dir(), 'oidc-key-');
    file_put_contents($file, ClientKeys::ec());

    try {
        $connection = keyJwtConnection(['key_path' => $file, 'algorithm' => 'ES256', 'key_id' => 'key-2026', 'audience' => 'issuer', 'headers' => ['x5t#S256' => 'abc'], 'lifetime_seconds' => 120]);
    } finally {
        unlink($file);
    }

    expect($connection->clientAssertion?->key->get('crv'))->toBe('P-256')
        ->and($connection->clientAssertion?->algorithm)->toBe(SigningAlgorithm::ES256)
        ->and($connection->clientAssertion?->keyId)->toBe('key-2026')
        ->and($connection->clientAssertion?->audience)->toBe(AssertionAudience::Issuer)
        ->and($connection->clientAssertion?->headers)->toBe(['x5t#S256' => 'abc'])
        ->and($connection->clientAssertion?->lifetimeSeconds)->toBe(120);
});

it('reads an Ed25519 key and an encrypted key with its passphrase', function (): void {
    expect(keyJwtConnection(['key' => ClientKeys::ed25519(), 'algorithm' => 'EdDSA'])->clientAssertion?->key->get('crv'))->toBe('Ed25519')
        ->and(keyJwtConnection(['key' => ClientKeys::encryptedRsa('s3cret'), 'passphrase' => 's3cret'])->clientAssertion?->key->get('kty'))->toBe('RSA');
});

it('refuses a client assertion setting it cannot use', function (array $assertion, string $key, string $problem): void {
    $exception = keyJwtRefusal($assertion);

    expect($exception->key())->toBe($key)
        ->and($exception->getMessage())->toContain($problem)
        ->and($exception->getMessage())->not->toContain('PRIVATE KEY');
})->with([
    'no key' => [[], 'oidc.connections.main.client_assertion.key', 'is required for client_auth private_key_jwt'],
    'key and key_path' => [['key' => ClientKeys::rsa(), 'key_path' => '/tmp/key.pem'], 'oidc.connections.main.client_assertion.key', 'is set together with key_path'],
    'not a key' => [['key' => 'not a key'], 'oidc.connections.main.client_assertion.key', 'is not a PEM private key the package can read'],
    'encrypted without passphrase' => [['key' => ClientKeys::encryptedRsa('s3cret')], 'oidc.connections.main.client_assertion.key', 'is not a PEM private key the package can read, or its passphrase is wrong'],
    'wrong passphrase' => [['key' => ClientKeys::encryptedRsa('s3cret'), 'passphrase' => 'wrong'], 'oidc.connections.main.client_assertion.key', 'its passphrase is wrong'],
    'public key' => [['key' => ClientKeys::publicRsa()], 'oidc.connections.main.client_assertion.key', 'is a public key'],
    'short RSA key' => [['key' => ClientKeys::rsa(1024)], 'oidc.connections.main.client_assertion.key', 'cannot sign RS256'],
    'EC key for RS256' => [['key' => ClientKeys::ec()], 'oidc.connections.main.client_assertion.key', 'cannot sign RS256: it is a EC key'],
    'P-384 key for ES256' => [['key' => ClientKeys::ec('secp384r1'), 'algorithm' => 'ES256'], 'oidc.connections.main.client_assertion.key', 'its curve is not P-256'],
    'HS256' => [['key' => ClientKeys::rsa(), 'algorithm' => 'HS256'], 'oidc.connections.main.client_assertion.algorithm', 'is not a supported signing algorithm'],
    'unknown audience' => [['key' => ClientKeys::rsa(), 'audience' => 'everyone'], 'oidc.connections.main.client_assertion.audience', 'is not a known assertion audience'],
    'reserved header' => [['key' => ClientKeys::rsa(), 'headers' => ['Alg' => 'none']], 'oidc.connections.main.client_assertion.headers.Alg', 'is set by the package itself'],
    'kid as a header' => [['key' => ClientKeys::rsa(), 'headers' => ['kid' => 'a']], 'oidc.connections.main.client_assertion.headers.kid', 'is set by the package itself'],
    'stream wrapper path' => [['key_path' => 'https://keys.example.test/key.pem'], 'oidc.connections.main.client_assertion.key_path', 'names no readable local file'],
    'data wrapper path' => [['key_path' => 'data://text/plain;base64,AAAA'], 'oidc.connections.main.client_assertion.key_path', 'names no readable local file'],
    'missing file' => [['key_path' => '/nonexistent/oidc-key.pem'], 'oidc.connections.main.client_assertion.key_path', 'names no readable local file'],
    'lifetime too long' => [['key' => ClientKeys::rsa(), 'lifetime_seconds' => 3600], 'oidc.connections.main.client_assertion.lifetime_seconds', 'must be a whole number from 10 to 600'],
]);

it('requires the client_assertion settings for private_key_jwt', function (): void {
    $exception = keyJwtRefusal([], ['client_assertion' => null]);

    expect($exception->key())->toBe('oidc.connections.main.client_assertion')
        ->and($exception->getMessage())->toContain('is required for client_auth private_key_jwt');
});

it('refuses the issuer as audience for a templated issuer', function (): void {
    $exception = keyJwtRefusal(['key' => ClientKeys::rsa(), 'audience' => 'issuer'], array_replace(ConnectionFixtures::entraMultiTenant(), ['client_secret' => null]));

    expect($exception->key())->toBe('oidc.connections.main.client_assertion.audience')
        ->and($exception->getMessage())->toContain('cannot be issuer when the issuer uses {tenantid}');
});

it('ignores client_assertion for the other methods', function (): void {
    $connection = OidcConfig::fromArray(['connections' => ['main' => ConnectionFixtures::minimal(['client_assertion' => ['key' => 'not a key']])]])->connection();

    expect($connection->clientAssertion)->toBeNull();
});

it('keeps the private key out of dumps', function (): void {
    $connection = keyJwtConnection(['key' => ClientKeys::rsa(), 'key_id' => 'k1']);

    expect(print_r($connection, true))->toContain('[redacted]')->toContain('k1')
        ->and(print_r($connection->clientAssertion, true))->not->toContain('"d"')
        ->and(var_export($connection->clientAssertion?->__debugInfo(), true))->not->toContain(ClientKeys::rsa());
});

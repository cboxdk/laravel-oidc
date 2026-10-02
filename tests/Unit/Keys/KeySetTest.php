<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\KeySetInvalid;
use Cbox\Oidc\Keys\KeySet;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Jose\Component\Core\JWK;

it('reads the public keys of a key set', function (): void {
    $set = KeySet::fromDocument(new FakeProvider()->jwks(), 'main', FakeProvider::JWKS_URL);

    expect($set->keys)->toHaveCount(3)
        ->and(array_map(static fn (JWK $key): mixed => $key->get('kid'), $set->keys))->toBe(['rsa-1', 'ec-1', 'ed-1']);
});

it('drops private members a provider publishes by mistake', function (): void {
    $private = FakeProvider::rsaKey('rsa-1')->all();
    $set = KeySet::fromDocument(['keys' => [$private]], 'main', FakeProvider::JWKS_URL);

    expect($private)->toHaveKey('d')
        ->and($set->keys[0]->has('d'))->toBeFalse()
        ->and($set->keys[0]->has('p'))->toBeFalse()
        ->and($set->keys[0]->get('n'))->toBe($private['n']);
});

it('skips keys without a kty, as RFC 7517 5 asks', function (): void {
    $set = KeySet::fromDocument(['keys' => [['kid' => 'no-type', 'n' => 'x'], ['kty' => 42], FakeProvider::edKey('ed-1')->toPublic()->all()]], 'main', FakeProvider::JWKS_URL);

    expect($set->keys)->toHaveCount(1)
        ->and($set->keys[0]->get('kid'))->toBe('ed-1');
});

it('keeps an empty key set; selection then finds nothing', function (): void {
    expect(KeySet::fromDocument(['keys' => []], 'main', FakeProvider::JWKS_URL)->keys)->toBe([]);
});

it('finds keys by kid', function (): void {
    $set = KeySet::fromDocument(new FakeProvider()->jwks(), 'main', FakeProvider::JWKS_URL);

    expect($set->withKid('ec-1'))->toHaveCount(1)
        ->and($set->withKid('missing'))->toBe([]);
});

it('refuses a document that is not a key set', function (array $document, string $problem): void {
    expect(fn (): KeySet => KeySet::fromDocument($document, 'main', FakeProvider::JWKS_URL))
        ->toThrow(function (KeySetInvalid $exception) use ($problem): void {
            expect($exception->errorCode())->toBe(ErrorCode::KeySetInvalid)
                ->and($exception->getMessage())->toContain('The key set of connection "main" at https://idp.example.test/oauth/jwks '.$problem);
        });
})->with([
    'no keys member' => [['issuer' => 'x'], 'has no "keys" list'],
    'keys is an object' => [['keys' => ['a' => ['kty' => 'RSA']]], 'has no "keys" list'],
    'keys is a string' => [['keys' => 'none'], 'has no "keys" list'],
    'an entry is a string' => [['keys' => ['key']], 'has an entry 0 that is not a JSON object'],
    'an entry is a list' => [['keys' => [['kty', 'RSA']]], 'has an entry 0 that is not a JSON object'],
    'too many keys' => [['keys' => array_fill(0, 101, ['kty' => 'oct'])], 'has 101 keys, more than the 100 the package reads'],
]);

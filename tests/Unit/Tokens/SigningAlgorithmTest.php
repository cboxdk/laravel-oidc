<?php

declare(strict_types=1);

use Cbox\Oidc\Tokens\SigningAlgorithm;

it('maps every algorithm to web-token with the same name', function (SigningAlgorithm $algorithm): void {
    expect($algorithm->signatureAlgorithm()->name())->toBe($algorithm->value);
})->with(SigningAlgorithm::cases());

it('knows the key type and curve of each algorithm', function (SigningAlgorithm $algorithm, string $kty, ?string $curve): void {
    expect($algorithm->signatureAlgorithm()->allowedKeyTypes())->toBe([$kty])
        ->and($algorithm->curve())->toBe($curve);
})->with([
    [SigningAlgorithm::RS256, 'RSA', null],
    [SigningAlgorithm::RS384, 'RSA', null],
    [SigningAlgorithm::RS512, 'RSA', null],
    [SigningAlgorithm::PS256, 'RSA', null],
    [SigningAlgorithm::PS384, 'RSA', null],
    [SigningAlgorithm::PS512, 'RSA', null],
    [SigningAlgorithm::ES256, 'EC', 'P-256'],
    [SigningAlgorithm::ES384, 'EC', 'P-384'],
    [SigningAlgorithm::ES512, 'EC', 'P-521'],
    [SigningAlgorithm::EdDSA, 'OKP', 'Ed25519'],
]);

it('hashes tokens with the hash of the algorithm, and SHA-512 for Ed25519', function (SigningAlgorithm $algorithm, string $hash, int $length): void {
    $expected = rtrim(strtr(base64_encode(substr(hash($hash, 'access-token', true), 0, intdiv(strlen(hash($hash, '', true)), 2))), '+/', '-_'), '=');

    expect($algorithm->tokenHash())->toBe($hash)
        ->and($algorithm->accessTokenHash('access-token'))->toBe($expected)->toHaveLength($length);
})->with([
    [SigningAlgorithm::RS256, 'sha256', 22],
    [SigningAlgorithm::PS256, 'sha256', 22],
    [SigningAlgorithm::ES256, 'sha256', 22],
    [SigningAlgorithm::RS384, 'sha384', 32],
    [SigningAlgorithm::PS384, 'sha384', 32],
    [SigningAlgorithm::ES384, 'sha384', 32],
    [SigningAlgorithm::RS512, 'sha512', 43],
    [SigningAlgorithm::PS512, 'sha512', 43],
    [SigningAlgorithm::ES512, 'sha512', 43],
    [SigningAlgorithm::EdDSA, 'sha512', 43],
]);

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

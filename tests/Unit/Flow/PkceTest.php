<?php

declare(strict_types=1);

use Cbox\Oidc\Flow\Pkce;

it('computes the S256 challenge of RFC 7636 appendix B', function (): void {
    expect(Pkce::challenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'))->toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

it('makes fresh 43-character verifiers of the unreserved characters', function (): void {
    $verifiers = array_map(Pkce::verifier(...), range(1, 20));

    expect(array_unique($verifiers))->toHaveCount(20);

    foreach ($verifiers as $verifier) {
        expect($verifier)->toMatch('/^[A-Za-z0-9_-]{43}$/');
    }
});

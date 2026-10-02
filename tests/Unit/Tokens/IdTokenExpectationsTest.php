<?php

declare(strict_types=1);

use Cbox\Oidc\Flow\AuthorizationTransaction;
use Cbox\Oidc\Tokens\IdTokenExpectations;

it('keeps the nonce and the access token out of dumps', function (): void {
    $transaction = new AuthorizationTransaction('main', 'state-1', 'nonce-secret', 'verifier-1', 'https://app.example.test/oidc/callback', 300, 1_790_000_000, ['urn:example:mfa']);
    $dump = print_r(IdTokenExpectations::forLogin($transaction, 'access-token-secret', 'https://idp.example.test'), true);

    expect($dump)->toContain('[redacted]')
        ->not->toContain('nonce-secret')
        ->not->toContain('access-token-secret')
        ->toContain('https://idp.example.test')
        ->toContain('urn:example:mfa')
        ->toContain('300');
});

it('shows which values are absent', function (): void {
    expect(new IdTokenExpectations(null)->__debugInfo())->toBe([
        'nonce' => null,
        'maxAge' => null,
        'accessToken' => null,
        'responseIssuer' => null,
        'renews' => null,
        'acrValues' => [],
    ]);
});

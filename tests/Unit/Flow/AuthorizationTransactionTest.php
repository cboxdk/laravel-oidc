<?php

declare(strict_types=1);

use Cbox\Oidc\Flow\AuthorizationTransaction;

function transaction(): AuthorizationTransaction
{
    return new AuthorizationTransaction('main', 'state-1', 'nonce-1', 'verifier-1', 'https://app.example.test/oidc/callback', 300, 1_790_000_000);
}

it('round-trips through its array form', function (): void {
    expect(AuthorizationTransaction::fromArray(transaction()->toArray()))->toEqual(transaction())
        ->and(AuthorizationTransaction::fromArray([...transaction()->toArray(), 'max_age' => null])?->maxAge)->toBeNull();
});

it('reads a damaged entry as no entry', function (mixed $values): void {
    expect(AuthorizationTransaction::fromArray($values))->toBeNull();
})->with([
    'not an array' => ['state-1'],
    'no state' => [array_diff_key(transaction()->toArray(), ['state' => true])],
    'empty nonce' => [[...transaction()->toArray(), 'nonce' => '']],
    'verifier that is not a string' => [[...transaction()->toArray(), 'code_verifier' => 42]],
    'created_at as a string' => [[...transaction()->toArray(), 'created_at' => '1790000000']],
    'max_age as a string' => [[...transaction()->toArray(), 'max_age' => '300']],
]);

it('keeps the nonce and the verifier out of dumps', function (): void {
    expect(print_r(transaction(), true))->not->toContain('nonce-1')->not->toContain('verifier-1')->toContain('state-1');
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Support\OAuthError;

it('keeps a valid OAuth error code', function (): void {
    expect(OAuthError::code('access_denied'))->toBe('access_denied')
        ->and(OAuthError::code('invalid_grant'))->toBe('invalid_grant');
});

it('replaces anything else', function (mixed $value): void {
    expect(OAuthError::code($value))->toBe(OAuthError::UNRECOGNIZED);
})->with([
    'empty' => [''],
    'a quote' => ['access"denied'],
    'a backslash' => ['access\\denied'],
    'markup' => ["<script>alert('x')</script>"],
    'a space' => ['access denied'],
    'a trailing newline' => ["access_denied\n"],
    'non-ASCII' => ['adgang_nægtet'],
    'too long' => [str_repeat('a', 65)],
    'a number' => [403],
    'a list' => [['access_denied']],
]);

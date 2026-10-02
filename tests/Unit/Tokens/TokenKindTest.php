<?php

declare(strict_types=1);

use Cbox\Oidc\Tokens\TokenKind;

it('lets an ID token carry any type but that of another kind of token', function (?string $type, bool $accepted): void {
    expect(TokenKind::IdToken->acceptsType($type))->toBe($accepted);
})->with([
    'none' => [null, true],
    'JWT' => ['JWT', true],
    'another value' => ['id_token', true],
    'a logout token' => ['logout+jwt', false],
    'an access token' => ['at+JWT', false],
]);

it('lets a logout token carry only its own type, JWT or none', function (?string $type, bool $accepted): void {
    expect(TokenKind::LogoutToken->acceptsType($type))->toBe($accepted);
})->with([
    'none' => [null, true],
    'logout+jwt' => ['logout+jwt', true],
    'the media type' => ['application/logout+jwt', true],
    'JWT' => ['jwt', true],
    'an access token' => ['at+jwt', false],
    'a security event' => ['secevent+jwt', false],
    'anything else' => ['id_token', false],
]);

it('names each kind in messages', function (): void {
    expect(TokenKind::IdToken->label())->toBe('ID token')
        ->and(TokenKind::LogoutToken->label())->toBe('logout token');
});

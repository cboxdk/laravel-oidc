<?php

declare(strict_types=1);

use Cbox\Oidc\Logout\LogoutToken;
use Cbox\Oidc\UserInfo\UserInfo;

function claimsOf(array $claims): UserInfo
{
    return new UserInfo('main', 'user-1', null, $claims);
}

it('reads each JSON type through its own reader, and null for any other', function (): void {
    $claims = claimsOf([
        'text' => 'a',
        'number' => 42,
        'numeric_text' => '42',
        'yes' => true,
        'no' => false,
        'true_text' => 'true',
        'roles' => ['admin', 'staff'],
        'mixed_list' => ['admin', 7],
        'map' => ['a' => 'b'],
        'when' => 1_790_000_000,
        'nothing' => null,
    ]);

    expect($claims->string('text'))->toBe('a')
        ->and($claims->string('number'))->toBeNull()
        ->and($claims->int('number'))->toBe(42)
        ->and($claims->int('numeric_text'))->toBeNull()
        ->and($claims->bool('yes'))->toBeTrue()
        ->and($claims->bool('no'))->toBeFalse()
        ->and($claims->bool('true_text'))->toBeNull()
        ->and($claims->stringList('roles'))->toBe(['admin', 'staff'])
        ->and($claims->stringList('mixed_list'))->toBeNull()
        ->and($claims->stringList('map'))->toBeNull()
        ->and($claims->stringList('text'))->toBeNull()
        ->and($claims->time('when')?->format(DATE_ATOM))->toBe('2026-09-21T14:13:20+00:00')
        ->and($claims->time('numeric_text'))->toBeNull()
        ->and($claims->int('missing'))->toBeNull()
        ->and($claims->has('nothing'))->toBeTrue()
        ->and($claims->has('missing'))->toBeFalse()
        ->and($claims->claim('map'))->toBe(['a' => 'b'])
        ->and($claims->claim('missing', 'fallback'))->toBe('fallback');
});

it('trusts email_verified only as the JSON value true', function (mixed $value, bool $verified): void {
    expect(claimsOf(['email' => 'ada@example.com', 'email_verified' => $value])->emailVerified())->toBe($verified);
})->with([
    'true' => [true, true],
    'false' => [false, false],
    'the string true' => ['true', false],
    '1' => [1, false],
]);

it('gives a logout token the same readers', function (): void {
    $token = new LogoutToken('main', 'https://idp.example.test', 'user-1', 'session-1', 'jti-1', new DateTimeImmutable('@1'), new DateTimeImmutable('@2'), [
        'events' => ['http://schemas.openid.net/event/backchannel-logout' => []],
        'iat' => 1,
        'sid' => 'session-1',
    ]);

    expect($token->string('sid'))->toBe('session-1')
        ->and($token->int('iat'))->toBe(1)
        ->and($token->time('iat')?->getTimestamp())->toBe(1)
        ->and($token->has('events'))->toBeTrue()
        ->and($token->claim('events'))->toBeArray()
        ->and($token->all())->toHaveKeys(['events', 'iat', 'sid']);
});

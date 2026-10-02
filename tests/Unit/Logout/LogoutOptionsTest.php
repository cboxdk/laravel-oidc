<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidLogoutOptions;
use Cbox\Oidc\Logout\LogoutOptions;

it('refuses an invalid option where it is written', function (Closure $make, string $message): void {
    expect($make)->toThrow(function (InvalidLogoutOptions $exception) use ($message): void {
        expect($exception->errorCode())->toBe(ErrorCode::LogoutOptionsInvalid)
            ->and($exception->getMessage())->toContain($message);
    });
})->with([
    'an id_token_hint that is not a JWT' => [fn (): LogoutOptions => new LogoutOptions(idTokenHint: 'not a token'), 'idTokenHint is not a compact JWT'],
    'an empty id_token_hint' => [fn (): LogoutOptions => new LogoutOptions(idTokenHint: ''), 'idTokenHint is not a compact JWT'],
    'a relative redirect' => [fn (): LogoutOptions => new LogoutOptions(postLogoutRedirectUri: '/bye'), 'postLogoutRedirectUri is not an absolute'],
    'a javascript redirect' => [fn (): LogoutOptions => new LogoutOptions(postLogoutRedirectUri: 'javascript:alert(1)'), 'postLogoutRedirectUri is not an absolute'],
    'a redirect with user info' => [fn (): LogoutOptions => new LogoutOptions(postLogoutRedirectUri: 'https://user@app.example.test/'), 'postLogoutRedirectUri is not an absolute'],
    'a redirect with a fragment' => [fn (): LogoutOptions => new LogoutOptions(postLogoutRedirectUri: 'https://app.example.test/#x'), 'postLogoutRedirectUri is not an absolute'],
    'an empty state' => [fn (): LogoutOptions => new LogoutOptions(state: ''), 'state is not 1 to 512'],
    'a state with a newline' => [fn (): LogoutOptions => new LogoutOptions(state: "a\nb"), 'state is not 1 to 512'],
    'a logout hint with a control character' => [fn (): LogoutOptions => new LogoutOptions(logoutHint: "ada\0"), 'logoutHint is not 1 to 255'],
    'a locale that is not a language tag' => [fn (): LogoutOptions => new LogoutOptions(uiLocales: ['en US']), 'uiLocales has "en US"'],
]);

it('accepts valid options', function (): void {
    $options = new LogoutOptions(idTokenHint: 'aGVhZGVy.cGF5bG9hZA.c2ln', postLogoutRedirectUri: 'http://localhost:8000/bye', state: 's', logoutHint: 'Ada', uiLocales: ['en', 'zh-Hant-TW']);

    expect($options->uiLocales)->toBe(['en', 'zh-Hant-TW']);
});

it('keeps the ID token out of dumps', function (): void {
    expect(print_r(new LogoutOptions(idTokenHint: 'aGVhZGVy.cGF5bG9hZA.c2ln'), true))->not->toContain('cGF5bG9hZA')->toContain('[redacted]');
});

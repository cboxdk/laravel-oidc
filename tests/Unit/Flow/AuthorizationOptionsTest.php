<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidAuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;

it('defaults to no options', function (): void {
    $options = new AuthorizationOptions;

    expect($options->prompts)->toBe([])
        ->and($options->maxAge)->toBeNull()
        ->and($options->loginHint)->toBeNull()
        ->and($options->scopes)->toBe([])
        ->and($options->acrValues)->toBe([])
        ->and($options->parameters)->toBe([]);
});

it('takes one prompt or several', function (): void {
    expect(new AuthorizationOptions(prompt: Prompt::Login)->prompts)->toBe([Prompt::Login])
        ->and(new AuthorizationOptions(prompt: [Prompt::Login, Prompt::Consent])->prompts)->toBe([Prompt::Login, Prompt::Consent]);
});

it('refuses invalid options where they are written', function (Closure $make, string $problem): void {
    expect($make)->toThrow(function (InvalidAuthorizationOptions $exception) use ($problem): void {
        expect($exception->errorCode())->toBe(ErrorCode::AuthorizationOptionsInvalid)
            ->and($exception->getMessage())->toContain($problem);
    });
})->with([
    'prompt none with another' => [fn (): AuthorizationOptions => new AuthorizationOptions(prompt: [Prompt::None, Prompt::Login]), 'prompt none is combined with another prompt'],
    'a prompt twice' => [fn (): AuthorizationOptions => new AuthorizationOptions(prompt: [Prompt::Login, Prompt::Login]), 'a prompt value is given twice'],
    'negative max age' => [fn (): AuthorizationOptions => new AuthorizationOptions(maxAge: -1), 'maxAge must be from 0 to 31536000 seconds'],
    'empty login hint' => [fn (): AuthorizationOptions => new AuthorizationOptions(loginHint: ''), 'loginHint must be 1 to 255 printable characters'],
    'login hint with a newline' => [fn (): AuthorizationOptions => new AuthorizationOptions(loginHint: "ada\n@example.com"), 'loginHint must be 1 to 255 printable characters'],
    'scope with a space' => [fn (): AuthorizationOptions => new AuthorizationOptions(scopes: ['a b']), '"a b" is not a valid scope or acr value'],
    'acr value with a quote' => [fn (): AuthorizationOptions => new AuthorizationOptions(acrValues: ['"mfa"']), 'is not a valid scope or acr value'],
    'reserved parameter' => [fn (): AuthorizationOptions => new AuthorizationOptions(parameters: ['Nonce' => 'x']), 'the parameter Nonce is set by the package itself'],
    'parameter with an option' => [fn (): AuthorizationOptions => new AuthorizationOptions(parameters: ['prompt' => 'login']), 'the parameter prompt is set by the package itself or has its own option'],
    'invalid parameter name' => [fn (): AuthorizationOptions => new AuthorizationOptions(parameters: ['a&b' => 'x']), '"a&b" is not a valid parameter name'],
    'long parameter value' => [fn (): AuthorizationOptions => new AuthorizationOptions(parameters: ['ui_locales' => str_repeat('a', 2049)]), 'the value of ui_locales is longer than 2048 bytes'],
]);

it('accepts a login hint with non-ASCII letters', function (): void {
    expect(new AuthorizationOptions(loginHint: 'søren@example.dk')->loginHint)->toBe('søren@example.dk');
});

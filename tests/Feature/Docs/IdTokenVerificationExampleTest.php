<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Tests\Support\FakeProvider;

/**
 * Runs the example of docs/core-concepts/id-token-verification.md with a
 * token of the fake provider, so the documented call keeps working.
 */
beforeEach(function (): void {
    $markdown = (string) file_get_contents(__DIR__.'/../../../docs/core-concepts/id-token-verification.md');
    expect(preg_match('/<!-- example: verify-id-token -->\n```php\n(.*?)```/s', $markdown, $match))->toBe(1);

    $this->example = (string) tempnam(sys_get_temp_dir(), 'oidc-verify-');
    file_put_contents($this->example, $match[1]);
    $this->provider = new FakeProvider()->install();
    $this->run = fn (string $idToken, string $nonce): mixed => (static fn (string $file, string $idToken, string $nonce): mixed => require $file)($this->example, $idToken, $nonce);
});

afterEach(function (): void {
    unlink($this->example);
});

it('verifies a token with the nonce the server issued', function (): void {
    expect(($this->run)($this->provider->idToken(['nonce' => 'n-1', 'sub' => 'app-user']), 'n-1'))->toBe([FakeProvider::ISSUER, 'app-user']);
});

it('refuses the token of another nonce', function (): void {
    expect(fn (): mixed => ($this->run)($this->provider->idToken(['nonce' => 'n-1']), 'n-2'))
        ->toThrow(function (TokenRejected $exception): void {
            expect($exception->errorCode())->toBe(ErrorCode::IdTokenNonceMismatch);
        });
});

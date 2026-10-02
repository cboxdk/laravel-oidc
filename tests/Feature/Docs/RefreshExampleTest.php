<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\VerifiedClaims;

/**
 * Runs the example of docs/core-concepts/refresh-and-userinfo.md against the
 * fake provider, so the documented refresh keeps working.
 */
beforeEach(function (): void {
    $markdown = (string) file_get_contents(__DIR__.'/../../../docs/core-concepts/refresh-and-userinfo.md');
    expect(preg_match('/<!-- example: refresh -->\n```php\n(.*?)```/s', $markdown, $match))->toBe(1);

    $this->example = (string) tempnam(sys_get_temp_dir(), 'oidc-refresh-');
    file_put_contents($this->example, $match[1]);
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->claims = resolve(IdTokenVerifier::class)->verify('main', $this->provider->idToken(['email' => 'ada@example.com']), new IdTokenExpectations('nonce-1'));
    $this->run = fn (VerifiedClaims $claims, string $refreshToken): mixed => (static fn (string $file, VerifiedClaims $claims, string $refreshToken): mixed => require $file)($this->example, $claims, $refreshToken);
});

afterEach(function (): void {
    unlink($this->example);
});

it('refreshes the tokens and reads userinfo with the new access token', function (): void {
    $refreshToken = $this->provider->issueRefreshToken($this->claims->claims);

    expect(($this->run)($this->claims, $refreshToken))->toBe(['user-1', true, 'ada@example.com'])
        ->and($this->provider->refreshTokenLive($refreshToken))->toBeFalse();
});

it('asks for a new sign-in when the provider ended the grant', function (): void {
    expect(($this->run)($this->claims, 'revoked-refresh-token'))->toBe('sign in again');
});

it('lets a new ID token for someone else fail loudly', function (): void {
    $this->provider->refreshClaims = ['sub' => 'user-2'];

    expect(fn (): mixed => ($this->run)($this->claims, $this->provider->issueRefreshToken($this->claims->claims)))->toThrow(TokenRejected::class);
});

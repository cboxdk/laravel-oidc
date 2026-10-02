<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\TokenEndpoint;
use Cbox\Oidc\Tokens\TokenSet;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Factory;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->answer = function (string $body, int $status = 200): TokenSet {
        $this->provider->tokenResponse = static fn (): PromiseInterface => Factory::response($body, $status, ['Content-Type' => 'application/json']);
        $connection = resolve(OidcConfig::class)->connection();

        return resolve(TokenEndpoint::class)->request($connection, resolve(MetadataRepository::class)->for($connection), ['grant_type' => 'refresh_token', 'refresh_token' => 'r']);
    };
});

it('reads a full token response', function (): void {
    $tokens = ($this->answer)('{"access_token":"at","token_type":"bearer","expires_in":"120","refresh_token":"rt","id_token":"it","scope":"openid  email"}');

    expect($tokens->accessToken)->toBe('at')
        ->and($tokens->tokenType)->toBe('Bearer')
        ->and($tokens->expiresIn)->toBe(120)
        ->and($tokens->expiresAt?->getTimestamp())->toBe(now()->getTimestamp() + 120)
        ->and($tokens->refreshToken)->toBe('rt')
        ->and($tokens->idToken)->toBe('it')
        ->and($tokens->scopes)->toBe(['openid', 'email']);
});

it('reads a minimal token response', function (): void {
    $tokens = ($this->answer)('{"access_token":"at","token_type":"Bearer"}');

    expect($tokens->expiresIn)->toBeNull()
        ->and($tokens->expiresAt)->toBeNull()
        ->and($tokens->refreshToken)->toBeNull()
        ->and($tokens->idToken)->toBeNull()
        ->and($tokens->scopes)->toBeNull();
});

it('refuses a token response the protocol does not allow', function (string $body, string $problem): void {
    expect(fn (): TokenSet => ($this->answer)($body))->toThrow(InvalidProviderResponse::class, $problem);
})->with([
    'not JSON' => ['<html>login</html>', 'it is not a JSON object with unique keys'],
    'a duplicate key' => ['{"access_token":"a","access_token":"b","token_type":"Bearer"}', 'it is not a JSON object with unique keys'],
    'no access token' => ['{"token_type":"Bearer"}', 'it has no access_token'],
    'an empty access token' => ['{"access_token":"","token_type":"Bearer"}', 'it has no access_token'],
    'no token type' => ['{"access_token":"a"}', 'it has no token_type'],
    'a DPoP token' => ['{"access_token":"a","token_type":"DPoP"}', 'its token_type is not Bearer'],
    'an ID token that is a number' => ['{"access_token":"a","token_type":"Bearer","id_token":1}', 'its id_token is not a non-empty string'],
    'an empty refresh token' => ['{"access_token":"a","token_type":"Bearer","refresh_token":""}', 'its refresh_token is not a non-empty string'],
    'a negative lifetime' => ['{"access_token":"a","token_type":"Bearer","expires_in":-1}', 'its expires_in is not a whole number of seconds'],
    'a fractional lifetime' => ['{"access_token":"a","token_type":"Bearer","expires_in":1.5}', 'its expires_in is not a whole number of seconds'],
    'a lifetime in words' => ['{"access_token":"a","token_type":"Bearer","expires_in":"an hour"}', 'its expires_in is not a whole number of seconds'],
]);

it('reports an OAuth error answer with its code', function (int $status, string $error, string $expected): void {
    expect(fn (): TokenSet => ($this->answer)(json_encode(['error' => $error, 'error_description' => 'secret detail']) ?: '', $status))
        ->toThrow(function (TokenRequestRejected $exception) use ($status, $expected): void {
            expect($exception->error())->toBe($expected)
                ->and($exception->getMessage())->toContain(sprintf('HTTP %d', $status))->not->toContain('secret detail');
        });
})->with([
    'invalid_grant' => [400, 'invalid_grant', 'invalid_grant'],
    'invalid_client with 401' => [401, 'invalid_client', 'invalid_client'],
    'an unregistered error' => [400, 'tenant_blocked', 'tenant_blocked'],
    'an error with markup' => [400, '<b>x</b>', 'unrecognized_error'],
]);

it('tells a temporary failure from a wrong answer', function (): void {
    expect(fn (): TokenSet => ($this->answer)('{"error":"slow_down"}', 429))->toThrow(ProviderUnavailable::class, 'HTTP 429')
        ->and(fn (): TokenSet => ($this->answer)('', 502))->toThrow(ProviderUnavailable::class, 'HTTP 502')
        ->and(fn (): TokenSet => ($this->answer)('<html>', 400))->toThrow(InvalidProviderResponse::class, 'HTTP 400')
        ->and(fn (): TokenSet => ($this->answer)('{"error":"x"}', 302))->toThrow(InvalidProviderResponse::class, 'HTTP 302');
});

it('keeps the tokens out of dumps', function (): void {
    $dump = print_r(($this->answer)('{"access_token":"at-secret","token_type":"Bearer","refresh_token":"rt-secret","id_token":"it-secret"}'), true);

    expect($dump)->not->toContain('at-secret')->not->toContain('rt-secret')->not->toContain('it-secret')->toContain('[redacted]');
});

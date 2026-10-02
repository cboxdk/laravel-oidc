<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidArgument;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\RevocationRejected;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Cbox\Oidc\Tokens\TokenRevocation;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Illuminate\Http\Client\Factory;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->revocation = fn (): TokenRevocation => resolve(TokenRevocation::class);
    $this->respond = function (string $body, int $status): void {
        $this->provider->revocationResponse = fn (): mixed => Factory::response($body, $status, ['Content-Type' => 'application/json']);
    };
});

it('revokes a refresh token with the client authentication of the connection', function (): void {
    $token = $this->provider->issueRefreshToken();

    ($this->revocation)()->revoke($token);

    expect($this->provider->refreshTokenLive($token))->toBeFalse()
        ->and($this->provider->revocationRequests[0]['form'])->toBe(['token' => $token, 'token_type_hint' => 'refresh_token'])
        ->and($this->provider->revocationRequests[0]['authorization'])->toBe('Basic '.base64_encode('client-1:secret-1'));
});

it('sends the hint it is given, or none', function (?TokenTypeHint $hint, array $form): void {
    ($this->revocation)()->revoke('token-1', $hint);

    expect($this->provider->revocationRequests[0]['form'])->toBe($form);
})->with([
    'an access token' => [TokenTypeHint::AccessToken, ['token' => 'token-1', 'token_type_hint' => 'access_token']],
    'no hint' => [null, ['token' => 'token-1']],
]);

it('authenticates as the connection says', function (): void {
    Refusals::useConnection('main', ConnectionFixtures::minimal(['client_auth' => 'client_secret_post']));

    ($this->revocation)()->revoke('token-1');

    expect($this->provider->revocationRequests[0]['form'])->toMatchArray(['client_id' => 'client-1', 'client_secret' => 'secret-1'])
        ->and($this->provider->revocationRequests[0]['authorization'])->toBeNull();
});

it('treats a token the provider does not know as revoked', function (): void {
    ($this->revocation)()->revoke('unknown-token');

    expect($this->provider->revocationRequests)->toHaveCount(1);
});

it('does not revoke the token of another client', function (): void {
    $token = $this->provider->issueRefreshToken(client: 'client-2');

    ($this->revocation)()->revoke($token);

    expect($this->provider->refreshTokenLive($token))->toBeTrue();
});

it('reports an OAuth error with its code', function (string $error, string $fix): void {
    ($this->respond)(json_encode(['error' => $error, 'error_description' => '<b>details</b>'], JSON_THROW_ON_ERROR), 400);

    $exception = Refusals::assert(fn () => ($this->revocation)()->revoke('token-1'), ErrorCode::RevocationRejected, RevocationRejected::class, 'the error '.$error);
    assert($exception instanceof RevocationRejected);

    expect($exception->error())->toBe($error)
        ->and($exception->fix())->toContain($fix)
        ->and($exception->getMessage())->not->toContain('details');
})->with([
    'invalid_client' => ['invalid_client', 'client_auth'],
    'unsupported_token_type' => ['unsupported_token_type', 'revoke the refresh token instead'],
    'another error' => ['invalid_request', 'error code names the cause'],
]);

it('refuses wrong client credentials', function (): void {
    $this->provider->clients = ['client-1' => ['secret' => 'another']];

    Refusals::assert(fn () => ($this->revocation)()->revoke('token-1'), ErrorCode::RevocationRejected, RevocationRejected::class, 'invalid_client');
});

it('reports a temporary failure as retryable', function (int $status): void {
    ($this->respond)('', $status);

    Refusals::assert(fn () => ($this->revocation)()->revoke('token-1'), ErrorCode::ProviderUnavailable, ProviderUnavailable::class);
})->with([503, 500, 429]);

it('refuses another answer', function (string $body, int $status): void {
    ($this->respond)($body, $status);

    Refusals::assert(fn () => ($this->revocation)()->revoke('token-1'), ErrorCode::ProviderResponseInvalid, InvalidProviderResponse::class, sprintf('HTTP %d', $status));
})->with([
    'a redirect' => ['', 302],
    'not found' => ['<html></html>', 404],
    'a 400 without an error' => ['{"message":"no"}', 400],
]);

it('needs the provider to advertise the endpoint', function (): void {
    unset($this->provider->discovery['revocation_endpoint']);

    expect(($this->revocation)()->supported())->toBeFalse();

    Refusals::assert(fn () => ($this->revocation)()->revoke('token-1'), ErrorCode::EndpointNotSupported, EndpointNotSupported::class, 'advertises no revocation_endpoint');
});

it('says when the endpoint is advertised, per connection', function (): void {
    $google = new FakeProvider('https://accounts.google.com')->install();
    $google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];
    unset($google->discovery['revocation_endpoint']);

    expect(($this->revocation)()->supported())->toBeTrue()
        ->and(($this->revocation)()->supported('workspace'))->toBeFalse();
});

it('refuses a malformed token before calling the provider', function (string $token): void {
    Refusals::assert(fn () => ($this->revocation)()->revoke($token), ErrorCode::ArgumentInvalid, InvalidArgument::class, 'The argument $token');

    expect($this->provider->revocationRequests)->toBe([]);
})->with(['', "a\nb", str_repeat('a', 16385)]);

it('sends the token only through the SSRF guard', function (): void {
    $this->provider->discovery['revocation_endpoint'] = 'https://metadata.example.test/revoke';

    Refusals::assert(fn () => ($this->revocation)()->revoke('token-1'), ErrorCode::HttpBlocked, OutboundRequestBlocked::class);
});

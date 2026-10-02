<?php

declare(strict_types=1);

use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Http\HttpResponse;
use Cbox\Oidc\Http\LaravelHttpClient;
use Cbox\Oidc\Http\ResponseTooLarge;
use GuzzleHttp\Psr7\Response as PsrResponse;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

it('is the default client', function (): void {
    expect(resolve(HttpClient::class))->toBeInstanceOf(LaravelHttpClient::class)
        ->and(resolve(HttpClient::class))->toBe(resolve(HttpClient::class));
});

it('sends a GET and returns status, lower-cased headers and body', function (): void {
    Http::fake(['https://idp.example.test/doc' => Http::response('{"a":1}', 200, ['Content-Type' => 'application/json', 'X-Trace' => ['a', 'b']])]);

    $response = resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc', ['Accept' => 'application/json']));

    expect($response)->toBeInstanceOf(HttpResponse::class)
        ->and($response->status)->toBe(200)
        ->and($response->body)->toBe('{"a":1}')
        ->and($response->header('content-type'))->toBe('application/json')
        ->and($response->header('X-TRACE'))->toBe('a, b')
        ->and($response->header('missing'))->toBeNull()
        ->and($response->successful())->toBeTrue();

    Http::assertSent(fn (Request $request): bool => $request->method() === 'GET' && $request->hasHeader('Accept', 'application/json'));
});

it('sends a form POST', function (): void {
    Http::fake(['https://idp.example.test/token' => Http::response('{}')]);

    resolve(HttpClient::class)->send(HttpRequest::postForm('https://idp.example.test/token', ['grant_type' => 'authorization_code', 'code' => 'c'], ['Authorization' => 'Basic eA==']));

    Http::assertSent(fn (Request $request): bool => $request->method() === 'POST'
        && $request->isForm()
        && $request['grant_type'] === 'authorization_code'
        && $request->hasHeader('Authorization', 'Basic eA=='));
});

it('returns a redirect as a response and never follows it', function (): void {
    Http::fake([
        'https://idp.example.test/moved' => Http::response('', 302, ['Location' => 'https://idp.example.test/elsewhere']),
        'https://idp.example.test/elsewhere' => Http::response('{}'),
    ]);

    $response = resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/moved'));

    expect($response->status)->toBe(302)
        ->and($response->successful())->toBeFalse();
    Http::assertSentCount(1);
});

it('passes other statuses back to the caller', function (int $status, bool $temporary): void {
    Http::fake(['https://idp.example.test/doc' => Http::response('nope', $status)]);

    $response = resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc'));

    expect($response->status)->toBe($status)
        ->and($response->temporaryFailure())->toBe($temporary);
})->with([
    [404, false],
    [400, false],
    [408, true],
    [429, true],
    [500, true],
    [503, true],
]);

it('lets the SSRF guard refuse a URL before anything is sent', function (string $url): void {
    Http::fake();

    expect(fn (): HttpResponse => resolve(HttpClient::class)->send(HttpRequest::get($url)))
        ->toThrow(function (OutboundRequestBlocked $exception): void {
            expect($exception->errorCode())->toBe(ErrorCode::HttpBlocked)
                ->and($exception->getMessage())->toContain('The SSRF guard refused a call to')
                ->and($exception->getMessage())->not->toContain('secret-code');
        });

    Http::assertNothingSent();
})->with([
    'http' => ['http://idp.example.test/doc?code=secret-code'],
    'a private address' => ['https://internal.example.test/doc?code=secret-code'],
    'the metadata address' => ['https://metadata.example.test/latest/meta-data'],
    'loopback by name' => ['https://localhost/doc'],
    'an IP literal' => ['https://127.0.0.1/doc'],
    'a host that does not resolve' => ['https://nowhere.example.test/doc'],
]);

it('refuses a body over the size limit', function (): void {
    config(['oidc.http.max_response_bytes' => 1024]);
    Http::fake(['https://idp.example.test/doc' => Http::response(str_repeat('a', 1025))]);

    expect(fn (): HttpResponse => resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc')))
        ->toThrow(function (InvalidProviderResponse $exception): void {
            expect($exception->errorCode())->toBe(ErrorCode::ProviderResponseInvalid)
                ->and($exception->getMessage())->toContain('larger than 1024 bytes')
                ->and($exception->fix())->toContain('oidc.http.max_response_bytes');
        });
});

it('accepts a body at the size limit', function (): void {
    config(['oidc.http.max_response_bytes' => 1024]);
    Http::fake(['https://idp.example.test/doc' => Http::response(str_repeat('a', 1024))]);

    expect(resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc'))->body)->toHaveLength(1024);
});

it('aborts a transfer whose Content-Length or download passes the limit', function (): void {
    $options = LaravelHttpClient::sizeLimitOptions(1024);

    expect(fn () => $options['on_headers'](new PsrResponse(200, ['Content-Length' => '1025'])))->toThrow(ResponseTooLarge::class)
        ->and(fn () => $options['progress'](0, 1025))->toThrow(ResponseTooLarge::class);

    $options['on_headers'](new PsrResponse(200, ['Content-Length' => '1024']));
    $options['on_headers'](new PsrResponse(200));
    $options['progress'](2048, 1024);
});

it('turns an aborted transfer into InvalidProviderResponse', function (): void {
    Http::fake(['https://idp.example.test/doc' => fn () => throw new ConnectionException('aborted', 0, new ResponseTooLarge)]);

    expect(fn (): HttpResponse => resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc')))
        ->toThrow(InvalidProviderResponse::class, 'larger than 262144 bytes');
});

it('reports a network failure as ProviderUnavailable', function (): void {
    Http::fake(['https://idp.example.test/doc' => fn () => throw new ConnectionException('cURL error 28: Operation timed out')]);

    expect(fn (): HttpResponse => resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc')))
        ->toThrow(function (ProviderUnavailable $exception): void {
            expect($exception->errorCode())->toBe(ErrorCode::ProviderUnavailable)
                ->and($exception->getMessage())->toContain('The provider at https://idp.example.test could not be reached: cURL error 28')
                ->and($exception->getPrevious())->toBeInstanceOf(ConnectionException::class);
        });
});

it('applies the configured timeouts and refuses redirects in the Guzzle options', function (): void {
    config(['oidc.http.timeout_seconds' => 3, 'oidc.http.connect_timeout_seconds' => 1.5]);
    $seen = [];
    Http::fake(['https://idp.example.test/doc' => function (Request $request, array $options) use (&$seen) {
        $seen = $options;

        return Http::response('{}');
    }]);

    resolve(HttpClient::class)->send(HttpRequest::get('https://idp.example.test/doc'));

    expect($seen)->toMatchArray(['allow_redirects' => false, 'timeout' => 3.0, 'connect_timeout' => 1.5])
        ->and($seen)->toHaveKeys(['on_headers', 'progress']);
});

it('hides form values and header values when dumped', function (): void {
    $request = HttpRequest::postForm('https://idp.example.test/token', ['client_secret' => 'top-secret'], ['Authorization' => 'Basic c2VjcmV0']);

    $dump = json_encode($request->__debugInfo(), JSON_THROW_ON_ERROR);

    expect($dump)->not->toContain('top-secret')
        ->and($dump)->not->toContain('c2VjcmV0')
        ->and($request->__debugInfo())->toMatchArray(['url' => 'https://idp.example.test/token', 'headers' => ['Authorization'], 'form' => ['client_secret']]);
});

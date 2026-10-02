<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\TransactionStore;
use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\CallbackRejected;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationTransaction;
use Cbox\Oidc\Flow\CallbackResult;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Illuminate\Http\Client\Request as ClientRequest;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Http;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->flow = fn (): AuthorizationFlow => resolve(AuthorizationFlow::class);
    $this->callback = fn (array $query, ?string $connection = null): CallbackResult => ($this->flow)()->callback(ConnectionFixtures::callbackRequest($query, $connection), $connection);
});

/**
 * @param  class-string<OidcException>  $class
 */
function rejectedWith(Closure $call, string $class, ErrorCode $code, string $message): void
{
    try {
        $call();
    } catch (OidcException $exception) {
        expect($exception)->toBeInstanceOf($class)
            ->and($exception->errorCode())->toBe($code)
            ->and($exception->getMessage())->toContain($message);

        return;
    }

    test()->fail(sprintf('Expected %s, but nothing was thrown.', $class));
}

it('exchanges the code of an approved login for tokens', function (): void {
    $request = ($this->flow)()->start();
    $result = ($this->callback)($this->provider->approve($request->url));

    expect($result->connection)->toBe('main')
        ->and($result->transaction->state)->toBe($request->state)
        ->and($result->responseIssuer)->toBe(FakeProvider::ISSUER)
        ->and($result->tokens->tokenType)->toBe('Bearer')
        ->and($result->tokens->accessToken)->toMatch('/^[0-9a-f]{32}$/')
        ->and($result->tokens->refreshToken)->toMatch('/^[0-9a-f]{32}$/')
        ->and($result->tokens->idToken)->toBeString()
        ->and($result->tokens->expiresIn)->toBe(3600)
        ->and($result->tokens->expiresAt?->getTimestamp())->toBe(now()->getTimestamp() + 3600)
        ->and($result->tokens->scopes)->toBe(['openid', 'profile', 'email']);

    $token = $this->provider->tokenRequests[0];

    expect($token['form'])->toMatchArray(['grant_type' => 'authorization_code', 'redirect_uri' => 'https://app.example.test/oidc/callback'])
        ->and($token['form'])->toHaveKeys(['code', 'code_verifier'])
        ->and($token['form'])->not->toHaveKeys(['client_id', 'client_secret'])
        ->and($token['authorization'])->toBe('Basic '.base64_encode('client-1:secret-1'));
});

it('returns the verified claims of the ID token', function (): void {
    $request = ($this->flow)()->start();
    $result = ($this->callback)($this->provider->approve($request->url, ['sub' => 'person-7', 'email' => 'ada@example.com', 'groups' => ['staff']]));

    expect($result->claims->connection)->toBe('main')
        ->and($result->claims->issuer)->toBe(FakeProvider::ISSUER)
        ->and($result->claims->subject)->toBe('person-7')
        ->and($result->claims->email())->toBe('ada@example.com')
        ->and($result->claims->groups)->toBe(['staff'])
        ->and($result->claims->authTime?->getTimestamp())->toBe(now()->getTimestamp())
        ->and($result->claims->has('at_hash'))->toBeTrue();
});

it('verifies the ID token with each algorithm the provider signs with', function (SigningAlgorithm $algorithm): void {
    $this->provider->idTokenAlgorithm = $algorithm;
    $result = ($this->callback)($this->provider->approve(($this->flow)()->start()->url));

    expect($result->claims->subject)->toBe('user-1');
})->with([SigningAlgorithm::RS256, SigningAlgorithm::ES256, SigningAlgorithm::EdDSA]);

it('refuses an ID token that does not belong to this login', function (array $claims, ErrorCode $code, string $message): void {
    $query = $this->provider->approve(($this->flow)()->start(options: new AuthorizationOptions(maxAge: 60))->url, $claims);

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), TokenRejected::class, $code, $message);
})->with([
    'the nonce of another login' => [['nonce' => 'another-login'], ErrorCode::IdTokenNonceMismatch, 'is not the nonce of this login'],
    'no nonce' => [['nonce' => null], ErrorCode::IdTokenNonceMismatch, 'has no nonce'],
    'an at_hash of another access token' => [['at_hash' => SigningAlgorithm::RS256->accessTokenHash('other')], ErrorCode::IdTokenAtHashMismatch, 'does not match the access token'],
    'no auth_time though max_age was sent' => [['auth_time' => null], ErrorCode::IdTokenAuthTimeInvalid, 'although the login sent max_age 60'],
    'an old sign-in though max_age was sent' => [fn (): array => ['auth_time' => now()->getTimestamp() - 3600], ErrorCode::IdTokenAuthTimeInvalid, 'longer than the max_age of 60 seconds'],
    'another audience' => [['aud' => 'client-2'], ErrorCode::TokenAudienceInvalid, 'is not for the client "client-1"'],
]);

it('refuses an ID token whose issuer differs from the callback\'s iss', function (): void {
    $query = $this->provider->approve(($this->flow)()->start()->url, ['iss' => 'https://evil.example.test']);
    $query['iss'] = FakeProvider::ISSUER;

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), TokenRejected::class, ErrorCode::TokenIssuerMismatch, 'names the issuer "https://evil.example.test"');
});

it('refuses an ID token from a token endpoint that sends one signed with another key', function (): void {
    $this->provider->tokenResponse = fn (): mixed => Http::response([
        'access_token' => 'a',
        'token_type' => 'Bearer',
        'id_token' => $this->provider->idToken(key: FakeProvider::rsaKey('forger', values: ['kid' => 'rsa-1'])),
    ]);

    rejectedWith(fn (): CallbackResult => ($this->callback)($this->provider->approve(($this->flow)()->start()->url)), TokenRejected::class, ErrorCode::TokenSignatureInvalid, 'does not verify');
});

it('carries the nonce the ID token must repeat', function (): void {
    $request = ($this->flow)()->start(options: new AuthorizationOptions(maxAge: 300));
    $result = ($this->callback)($this->provider->approve($request->url));
    $claims = json_decode(base64_decode(strtr(explode('.', (string) $result->tokens->idToken)[1], '-_', '+/'), true), true, 8, JSON_THROW_ON_ERROR);

    expect($claims['nonce'])->toBe($result->transaction->nonce)
        ->and($result->transaction->maxAge)->toBe(300);
});

it('uses a login once', function (): void {
    $query = $this->provider->approve(($this->flow)()->start()->url);
    ($this->callback)($query);

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::StateMismatch, 'no login of this session matches its state');
    expect($this->provider->tokenRequests)->toHaveCount(1);
});

it('keeps several logins of one session apart', function (): void {
    $first = ($this->flow)()->start();
    $second = ($this->flow)()->start();

    expect(($this->callback)($this->provider->approve($second->url))->transaction->state)->toBe($second->state)
        ->and(($this->callback)($this->provider->approve($first->url))->transaction->state)->toBe($first->state);
});

it('refuses a callback whose state matches no login', function (array $query, string $problem): void {
    ($this->flow)()->start();

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::StateMismatch, $problem);
    expect($this->provider->tokenRequests)->toBe([]);
})->with([
    'no state' => [['code' => 'abc'], 'it has no state parameter'],
    'an empty state' => [['code' => 'abc', 'state' => ''], 'it has no state parameter'],
    'an unknown state' => [['code' => 'abc', 'state' => 'forged'], 'no login of this session matches its state'],
    'a very long state' => [['code' => 'abc', 'state' => str_repeat('a', 513)], 'its state is longer than any state the package makes'],
]);

it('refuses a forged error answer that has no valid state', function (): void {
    ($this->flow)()->start();

    rejectedWith(fn (): CallbackResult => ($this->callback)(['error' => 'access_denied', 'state' => 'forged']), CallbackRejected::class, ErrorCode::StateMismatch, 'no login of this session matches its state');
});

it('refuses the state of another connection\'s login', function (): void {
    config(['oidc.connections.second' => ConnectionFixtures::minimal(['redirect_uri' => 'https://app.example.test/oidc/second/callback'])]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(AuthorizationFlow::class);

    $query = $this->provider->approve(($this->flow)()->start('second')->url);

    rejectedWith(fn (): CallbackResult => ($this->callback)($query, 'main'), CallbackRejected::class, ErrorCode::StateMismatch, 'its state belongs to a login of connection "second"');
    // The login was used up by the refused attempt.
    rejectedWith(fn (): CallbackResult => ($this->callback)($query, 'second'), CallbackRejected::class, ErrorCode::StateMismatch, 'no login of this session matches its state');
});

it('refuses a login older than the transaction lifetime', function (): void {
    config(['oidc.flow.transaction_ttl_seconds' => 120]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(AuthorizationFlow::class);

    $query = $this->provider->approve(($this->flow)()->start()->url);
    $this->travel(121)->seconds();

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::TransactionExpired, 'was started 121 seconds ago, longer than the 120 seconds a login may take');
});

it('accepts a login at the end of its lifetime', function (): void {
    $query = $this->provider->approve(($this->flow)()->start()->url);
    $this->travel(600)->seconds();

    expect(($this->callback)($query)->tokens->tokenType)->toBe('Bearer');
});

it('refuses a callback that arrives at another connection\'s redirect_uri, also without iss (mix-up)', function (): void {
    $request = ($this->flow)()->start();
    $query = $this->provider->approve($request->url);
    unset($query['iss']);

    // An application whose one callback route takes the connection from the
    // session: the browser came back to the workspace connection's URL.
    $arrived = Request::create('https://app.example.test/oidc/workspace/callback', 'GET', $query);

    rejectedWith(fn () => ($this->flow)()->callback($arrived, 'main'), CallbackRejected::class, ErrorCode::CallbackUrlMismatch, 'arrived at app.example.test/oidc/workspace/callback, but its login was started with the redirect_uri https://app.example.test/oidc/callback');

    expect($this->provider->tokenRequests)->toBe([])
        ->and(fn () => ($this->callback)($query))->toThrow(CallbackRejected::class, '[oidc_state_mismatch]');
});

it('refuses a callback on another host than the redirect_uri', function (): void {
    $request = ($this->flow)()->start();
    $arrived = Request::create('https://evil.example.test/oidc/callback', 'GET', $this->provider->approve($request->url));

    rejectedWith(fn () => ($this->flow)()->callback($arrived), CallbackRejected::class, ErrorCode::CallbackUrlMismatch, 'arrived at evil.example.test/oidc/callback');
});

it('accepts a callback whose scheme or port a proxy changed', function (string $url): void {
    $request = ($this->flow)()->start();
    $arrived = Request::create($url, 'GET', $this->provider->approve($request->url));

    expect(($this->flow)()->callback($arrived)->connection)->toBe('main');
})->with([
    'http behind a proxy that ends TLS' => ['http://app.example.test/oidc/callback'],
    'an internal port' => ['http://app.example.test:8080/oidc/callback'],
    'another case of the host' => ['https://APP.example.test/oidc/callback'],
    'a trailing slash' => ['https://app.example.test/oidc/callback/'],
]);

it('refuses an iss parameter that is not the pinned issuer (RFC 9207)', function (): void {
    $query = [...$this->provider->approve(($this->flow)()->start()->url), 'iss' => 'https://evil.example.test'];

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::CallbackIssuerMismatch, 'names the issuer "https://evil.example.test", but the connection pins "https://idp.example.test"');
    expect($this->provider->tokenRequests)->toBe([]);
});

it('requires the iss parameter when the provider announces it', function (): void {
    $query = $this->provider->approve(($this->flow)()->start()->url);
    unset($query['iss']);

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::CallbackIssuerMismatch, 'has no iss parameter, although the provider announces it');
});

it('checks iss when present even if the provider does not announce it', function (): void {
    $this->provider->discovery['authorization_response_iss_parameter_supported'] = false;
    $query = $this->provider->approve(($this->flow)()->start()->url);
    unset($query['iss']);

    expect(($this->callback)($query)->responseIssuer)->toBeNull();

    $query = [...$this->provider->approve(($this->flow)()->start()->url), 'iss' => FakeProvider::ISSUER.'/'];

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::CallbackIssuerMismatch, 'names the issuer "https://idp.example.test/"');
});

it('reads an Entra iss parameter against the issuer template', function (string $iss, bool $accepted): void {
    $entra = FakeProvider::entra()->install();
    $entra->clients['00000000-0000-0000-0000-000000000001'] = ['secret' => 'entra-secret'];
    config(['oidc.connections.entra' => ConnectionFixtures::entraMultiTenant()]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(AuthorizationFlow::class);

    $query = [...$entra->approve(($this->flow)()->start('entra')->url, ['tid' => '11111111-1111-1111-1111-111111111111']), 'iss' => $iss];

    if ($accepted) {
        expect(($this->callback)($query, 'entra')->responseIssuer)->toBe($iss);
    } else {
        rejectedWith(fn (): CallbackResult => ($this->callback)($query, 'entra'), CallbackRejected::class, ErrorCode::CallbackIssuerMismatch, 'names the issuer');
    }
})->with([
    'a tenant' => ['https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0', true],
    'the template itself' => ['https://login.microsoftonline.com/{tenantid}/v2.0', false],
    'two path segments' => ['https://login.microsoftonline.com/a/b/v2.0', false],
    'another host' => ['https://login.example.test/11111111-1111-1111-1111-111111111111/v2.0', false],
    'a trailing newline' => ["https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0\n", false],
]);

it('reports the provider\'s error code and nothing of its description', function (): void {
    $query = $this->provider->deny(($this->flow)()->start()->url, 'access_denied');

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(function (AuthorizationDenied $exception): void {
        expect($exception->errorCode())->toBe(ErrorCode::AuthorizationDenied)
            ->and($exception->error())->toBe('access_denied')
            ->and($exception->interactionRequired())->toBeFalse()
            ->and($exception->getMessage())->toContain('answered the login with the error access_denied')->not->toContain('script');
    });
    expect($this->provider->tokenRequests)->toBe([]);
});

it('tells a silent login that needs interaction apart', function (): void {
    $query = $this->provider->deny(($this->flow)()->start(options: new AuthorizationOptions(prompt: Prompt::None))->url, 'login_required');

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(function (AuthorizationDenied $exception): void {
        expect($exception->interactionRequired())->toBeTrue()
            ->and($exception->fix())->toContain('Start a normal login');
    });
});

it('replaces an error code that is not one', function (): void {
    $query = [...$this->provider->deny(($this->flow)()->start()->url), 'error' => '<img src=x onerror=alert(1)>'];

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(function (AuthorizationDenied $exception): void {
        expect($exception->error())->toBe('unrecognized_error')
            ->and($exception->getMessage())->not->toContain('<img');
    });
});

it('refuses a callback without a usable code', function (array $changes, string $problem): void {
    $query = array_filter([...$this->provider->approve(($this->flow)()->start()->url), ...$changes], static fn (mixed $value): bool => $value !== null);

    rejectedWith(fn (): CallbackResult => ($this->callback)($query), CallbackRejected::class, ErrorCode::CallbackInvalid, $problem);
    expect($this->provider->tokenRequests)->toBe([]);
})->with([
    'no code' => [['code' => null], 'has neither a code nor an error'],
    'a code with a newline' => [['code' => "abc\ndef"], 'has a code that is not 1 to 2048 printable ASCII characters'],
    'a very long code' => [['code' => str_repeat('a', 2049)], 'has a code that is not 1 to 2048 printable ASCII characters'],
    'a code as a list' => [['code' => ['a', 'b']], 'carries code in a form other than one string'],
]);

it('refuses a state given as a list', function (): void {
    $query = $this->provider->approve(($this->flow)()->start()->url);

    rejectedWith(fn (): CallbackResult => ($this->callback)([...$query, 'state' => [$query['state']]]), CallbackRejected::class, ErrorCode::CallbackInvalid, 'carries state in a form other than one string');
});

it('reports a rejected code exchange with the error code only', function (): void {
    $request = ($this->flow)()->start();
    $query = $this->provider->approve($request->url);
    $query['code'] = 'another-code';

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(function (TokenRequestRejected $exception): void {
        expect($exception->errorCode())->toBe(ErrorCode::TokenRequestRejected)
            ->and($exception->error())->toBe('invalid_grant')
            ->and($exception->getMessage())->toContain('refused the request with HTTP 400 and the error invalid_grant')->not->toContain('<b>')
            ->and($exception->fix())->toContain('Start the login again');
    });
});

it('reports wrong client credentials', function (): void {
    $this->provider->clients['client-1']['secret'] = 'rotated';
    $query = $this->provider->approve(($this->flow)()->start()->url);

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(function (TokenRequestRejected $exception): void {
        expect($exception->error())->toBe('invalid_client')
            ->and($exception->fix())->toContain('Check client_id, client_secret');
    });
});

it('sends the verifier the code was issued for', function (): void {
    $request = ($this->flow)()->start();
    $query = $this->provider->approve($request->url);

    // Another login's verifier: the provider refuses the code.
    $other = ($this->flow)()->start();
    $store = resolve(TransactionStore::class);
    $mine = $store->pull($request->state);
    $theirs = $store->pull($other->state);
    $store->put(new AuthorizationTransaction('main', $request->state, (string) $mine?->nonce, (string) $theirs?->codeVerifier, (string) $mine?->redirectUri, null, (int) $mine?->createdAt));

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(TokenRequestRejected::class, 'invalid_grant');
});

it('reports a token endpoint that is down as unavailable', function (): void {
    $this->provider->tokenResponse = fn (): mixed => Http::response('busy', 503);
    $query = $this->provider->approve(($this->flow)()->start()->url);

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(ProviderUnavailable::class, 'HTTP 503');
});

it('refuses a token response without an ID token', function (): void {
    $this->provider->tokenResponse = fn (): mixed => Http::response(['access_token' => 'a', 'token_type' => 'Bearer']);
    $query = $this->provider->approve(($this->flow)()->start()->url);

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(InvalidProviderResponse::class, 'it has no id_token');
});

it('sends the token request through the SSRF guard', function (): void {
    $this->provider->discovery['token_endpoint'] = 'https://internal.example.test/oauth/token';
    $query = $this->provider->approve(($this->flow)()->start()->url);

    expect(fn (): CallbackResult => ($this->callback)($query))->toThrow(OutboundRequestBlocked::class);
    Http::assertNotSent(fn (ClientRequest $request): bool => str_contains($request->url(), 'internal.example.test'));
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\TransactionStore;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationRequest;
use Cbox\Oidc\Flow\Pkce;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Flow\SessionTransactionStore;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Contracts\Session\Session;
use Illuminate\Support\Facades\Route;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->flow = fn (): AuthorizationFlow => resolve(AuthorizationFlow::class);
    $this->query = static function (string $url): array {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return $query;
    };
});

/**
 * @param  array<string, mixed>  $connection
 */
function reconfigure(array $connection, string $name = 'main'): void
{
    config(["oidc.connections.$name" => $connection]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(AuthorizationFlow::class);
}

it('sends the browser to the authorization endpoint with every protocol parameter', function (): void {
    $request = ($this->flow)()->start();
    $query = ($this->query)($request->url);

    expect($request)->toBeInstanceOf(AuthorizationRequest::class)
        ->and($request->connection)->toBe('main')
        ->and($request->url)->toStartWith(FakeProvider::AUTHORIZATION_URL.'?response_type=code&client_id=client-1&redirect_uri=https%3A%2F%2Fapp.example.test%2Foidc%2Fcallback&scope=openid%20profile%20email&state=')
        ->and(array_keys($query))->toBe(['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'])
        ->and($query['state'])->toBe($request->state)->toMatch('/^[A-Za-z0-9_-]{43}$/')
        ->and($query['nonce'])->toMatch('/^[A-Za-z0-9_-]{43}$/')->not->toBe($query['state'])
        ->and($query['code_challenge_method'])->toBe('S256');

    $transaction = resolve(TransactionStore::class)->pull($request->state);

    expect($transaction?->connection)->toBe('main')
        ->and($transaction?->nonce)->toBe($query['nonce'])
        ->and(Pkce::challenge((string) $transaction?->codeVerifier))->toBe($query['code_challenge'])
        ->and($transaction?->redirectUri)->toBe('https://app.example.test/oidc/callback')
        ->and($transaction?->maxAge)->toBeNull()
        ->and($transaction?->createdAt)->toBe(now()->getTimestamp());
});

it('makes a fresh state, nonce and verifier for every login', function (): void {
    $first = ($this->query)(($this->flow)()->start()->url);
    $second = ($this->query)(($this->flow)()->start()->url);

    expect($second['state'])->not->toBe($first['state'])
        ->and($second['nonce'])->not->toBe($first['nonce'])
        ->and($second['code_challenge'])->not->toBe($first['code_challenge']);
});

it('adds the options to the request', function (): void {
    $url = ($this->flow)()->start(options: new AuthorizationOptions(
        prompt: [Prompt::Login, Prompt::Consent],
        maxAge: 0,
        loginHint: 'ada+test@example.com',
        scopes: ['offline_access', 'email'],
        acrValues: ['urn:mfa', 'pwd'],
        parameters: ['ui_locales' => 'da en'],
    ))->url;
    $query = ($this->query)($url);

    expect($query['scope'])->toBe('openid profile email offline_access')
        ->and($query['max_age'])->toBe('0')
        ->and($query['prompt'])->toBe('login consent')
        ->and($query['login_hint'])->toBe('ada+test@example.com')
        ->and($query['acr_values'])->toBe('urn:mfa pwd')
        ->and($query['ui_locales'])->toBe('da en')
        ->and($url)->toContain('login_hint=ada%2Btest%40example.com')->toContain('prompt=login%20consent');
});

it('sends the connection\'s max_age and keeps it for the token check', function (): void {
    reconfigure(ConnectionFixtures::minimal(['max_age' => 3600]));
    $request = ($this->flow)()->start();

    expect(($this->query)($request->url)['max_age'])->toBe('3600')
        ->and(resolve(TransactionStore::class)->pull($request->state)?->maxAge)->toBe(3600);

    $request = ($this->flow)()->start(options: new AuthorizationOptions(maxAge: 60));

    expect(($this->query)($request->url)['max_age'])->toBe('60')
        ->and(resolve(TransactionStore::class)->pull($request->state)?->maxAge)->toBe(60);
});

it('adds the connection\'s parameters, which the options replace', function (): void {
    config(['oidc.connections.main.authorization_parameters' => ['access_type' => 'offline', 'prompt' => 'consent', 'ui_locales' => 'en']]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(AuthorizationFlow::class);

    expect(($this->query)(($this->flow)()->start()->url))->toMatchArray(['access_type' => 'offline', 'prompt' => 'consent', 'ui_locales' => 'en'])
        ->and(($this->query)(($this->flow)()->start(options: new AuthorizationOptions(prompt: Prompt::SelectAccount, parameters: ['ui_locales' => 'da']))->url))
        ->toMatchArray(['access_type' => 'offline', 'prompt' => 'select_account', 'ui_locales' => 'da']);
});

it('keeps the query of the authorization endpoint', function (): void {
    $this->provider->discovery['authorization_endpoint'] = FakeProvider::AUTHORIZATION_URL.'?p=b2c_1_signin';

    $url = ($this->flow)()->start()->url;

    expect($url)->toStartWith(FakeProvider::AUTHORIZATION_URL.'?p=b2c_1_signin&response_type=code&');
});

it('refuses an authorization endpoint whose query sets a parameter of the request', function (): void {
    $this->provider->discovery['authorization_endpoint'] = FakeProvider::AUTHORIZATION_URL.'?Client_ID=other';

    expect(fn (): AuthorizationRequest => ($this->flow)()->start())
        ->toThrow(DiscoveryFailed::class, 'has an authorization_endpoint whose query already sets client_id');
});

it('refuses to send the browser to a private address', function (): void {
    $this->provider->discovery['authorization_endpoint'] = 'https://10.0.0.5/oauth/authorize';

    expect(fn (): AuthorizationRequest => ($this->flow)()->start())
        ->toThrow(function (OutboundRequestBlocked $exception): void {
            expect($exception->errorCode())->toBe(ErrorCode::HttpBlocked)
                ->and($exception->getMessage())->toContain('refused to send the browser to https://10.0.0.5');
        });

    expect(resolve(Session::class)->get(SessionTransactionStore::SESSION_KEY))->toBeNull();
});

it('starts a login of a named connection', function (): void {
    reconfigure(ConnectionFixtures::minimal(['client_id' => 'client-2', 'redirect_uri' => 'https://app.example.test/oidc/second/callback']), 'second');

    $request = ($this->flow)()->start('second');

    expect($request->connection)->toBe('second')
        ->and(($this->query)($request->url))->toMatchArray(['client_id' => 'client-2', 'redirect_uri' => 'https://app.example.test/oidc/second/callback'])
        ->and(fn (): AuthorizationRequest => ($this->flow)()->start('missing'))->toThrow(UnknownConnection::class);
});

it('answers with a redirect when returned from a route', function (): void {
    Route::middleware('web')->get('/login', fn (): AuthorizationRequest => resolve(AuthorizationFlow::class)->start());

    $response = $this->get('/login');

    $response->assertRedirect();

    expect($response->headers->get('Location'))->toStartWith(FakeProvider::AUTHORIZATION_URL.'?');

    expect(($this->flow)()->redirect()->getTargetUrl())->toStartWith(FakeProvider::AUTHORIZATION_URL.'?');
});

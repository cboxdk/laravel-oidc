<?php

declare(strict_types=1);

use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\OidcConnection;
use Cbox\Oidc\OidcManager;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Illuminate\Http\Request;

/**
 * The facade and the OidcClient contract run the real services: these tests
 * sign in against the in-process provider through them.
 */
beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->callbackRequest = fn (array $query, ?string $connection = null): Request => ConnectionFixtures::callbackRequest($query, $connection);
});

it('binds the contract to the manager behind the facade', function (): void {
    expect(resolve(OidcClient::class))->toBeInstanceOf(OidcManager::class)
        ->and(Oidc::getFacadeRoot())->toBe(resolve(OidcClient::class));
});

it('signs a person in through redirect and callback', function (): void {
    $redirect = Oidc::redirect();

    expect($redirect->getTargetUrl())->toStartWith(FakeProvider::AUTHORIZATION_URL.'?');

    $result = Oidc::callback(request: ($this->callbackRequest)($this->provider->approve($redirect->getTargetUrl(), ['sub' => 'ada'])));

    expect($result->connection)->toBe('main')
        ->and($result->claims->issuer)->toBe(FakeProvider::ISSUER)
        ->and($result->claims->subject)->toBe('ada');
});

it('reads the callback from the current request when none is passed', function (): void {
    $request = Oidc::start(options: new AuthorizationOptions(prompt: Prompt::Login));
    parse_str((string) parse_url($request->url, PHP_URL_QUERY), $query);

    expect($query['prompt'])->toBe('login');

    $this->app->instance('request', ($this->callbackRequest)($this->provider->approve($request->url)));

    expect(Oidc::callback()->transaction->state)->toBe($request->state);
});

it('binds the calls to one connection', function (): void {
    $google = new FakeProvider('https://accounts.google.com')->install();
    $google->clients = ['google-client' => ['secret' => 'google-secret']];
    $google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];

    $workspace = Oidc::connection('workspace');
    $request = $workspace->start();

    expect($workspace)->toBeInstanceOf(OidcConnection::class)
        ->and($workspace->name)->toBe('workspace')
        ->and($request->connection)->toBe('workspace')
        ->and($request->url)->toStartWith($google->authorizationUrl.'?')
        ->and($workspace->redirect()->getTargetUrl())->toStartWith($google->authorizationUrl.'?');

    $result = $workspace->callback(($this->callbackRequest)($google->approve($request->url, ['hd' => 'example.com']), 'workspace'));

    expect($result->claims->tenant)->toBe('example.com')
        ->and(Oidc::connection()->name)->toBe('main');
});

it('refuses a connection that is not configured', function (): void {
    expect(fn () => Oidc::connection('nope'))->toThrow(UnknownConnection::class, '[oidc_connection_unknown]')
        ->and(fn () => Oidc::redirect('nope'))->toThrow(UnknownConnection::class);
});

it('refreshes, reads userinfo, logs out and revokes', function (): void {
    $request = Oidc::start();
    $login = Oidc::callback(request: ($this->callbackRequest)($this->provider->approve($request->url, ['email' => 'ada@example.com'])));

    $renewed = Oidc::refresh($login->claims, (string) $login->tokens->refreshToken);
    $info = Oidc::userInfo($renewed->claims, $renewed->tokens->accessToken);

    expect($renewed->claims->subject)->toBe('user-1')
        ->and($info->email())->toBe('ada@example.com');

    $logout = Oidc::logout(options: new LogoutOptions(idTokenHint: $login->tokens->idToken));

    expect($logout->getTargetUrl())->toStartWith($this->provider->endSessionUrl.'?');

    Oidc::revoke($renewed->refreshToken);

    expect($this->provider->revocationRequests)->toHaveCount(1)
        ->and($this->provider->refreshTokenLive($renewed->refreshToken))->toBeFalse();
});

it('falls back on logout when the provider has no end_session_endpoint', function (): void {
    unset($this->provider->discovery['end_session_endpoint']);

    expect(Oidc::logout(fallback: '/bye')->getTargetUrl())->toEndWith('/bye')
        ->and(Oidc::connection()->logout(fallback: '/home')->getTargetUrl())->toEndWith('/home');
});

it('revokes through a connection', function (): void {
    Oidc::connection('main')->revoke('access-token-1', TokenTypeHint::AccessToken);

    expect($this->provider->revocationRequests[0]['form'])->toBe(['token' => 'access-token-1', 'token_type_hint' => 'access_token']);
});

it('passes on the coded errors of the services', function (): void {
    unset($this->provider->discovery['revocation_endpoint']);

    try {
        Oidc::revoke('token-1');
        $this->fail('Expected EndpointNotSupported.');
    } catch (EndpointNotSupported $exception) {
        expect($exception->errorCode())->toBe(ErrorCode::EndpointNotSupported)
            ->and($exception->endpoint())->toBe('revocation_endpoint');
    }
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Logout\LogoutFlow;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Illuminate\Http\Request;

beforeEach(function (): void {
    $this->provider = new FakeProvider()->install();
    $this->flow = fn (): LogoutFlow => resolve(LogoutFlow::class);
    $this->query = function (string $url): array {
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);

        return $query;
    };
});

it('sends the browser to the end_session_endpoint with the client id', function (): void {
    $request = ($this->flow)()->start();

    expect($request->connection)->toBe('main')
        ->and($request->url)->toStartWith($this->provider->endSessionUrl.'?')
        ->and(($this->query)($request->url))->toBe(['client_id' => 'client-1']);
});

it('adds every option it is given', function (): void {
    $idToken = $this->provider->idToken();
    $request = ($this->flow)()->start(options: new LogoutOptions(
        idTokenHint: $idToken,
        postLogoutRedirectUri: 'https://app.example.test/bye',
        state: 'state-1',
        logoutHint: 'ada@example.com',
        uiLocales: ['da-DK', 'en'],
    ));

    expect(($this->query)($request->url))->toBe([
        'client_id' => 'client-1',
        'id_token_hint' => $idToken,
        'post_logout_redirect_uri' => 'https://app.example.test/bye',
        'state' => 'state-1',
        'logout_hint' => 'ada@example.com',
        'ui_locales' => 'da-DK en',
    ]);
});

it('uses the connection\'s post_logout_redirect_uri unless the options name one', function (): void {
    Refusals::useConnection('main', ConnectionFixtures::minimal(['post_logout_redirect_uri' => 'https://app.example.test/signed-out']));

    expect(($this->query)(($this->flow)()->start()->url)['post_logout_redirect_uri'])->toBe('https://app.example.test/signed-out')
        ->and(($this->query)(($this->flow)()->start(options: new LogoutOptions(postLogoutRedirectUri: 'https://app.example.test/other'))->url)['post_logout_redirect_uri'])->toBe('https://app.example.test/other');
});

it('answers as a redirect when returned from a route', function (): void {
    $request = ($this->flow)()->start();
    $response = $request->toResponse(Request::create('/logout'));

    expect($response->getStatusCode())->toBe(302)
        ->and($response->headers->get('Location'))->toBe($request->url);
});

it('keeps the endpoint\'s own query', function (): void {
    $this->provider->discovery['end_session_endpoint'] = $this->provider->endSessionUrl.'?p=b2c_signin';

    expect(($this->flow)()->start()->url)->toBe($this->provider->endSessionUrl.'?p=b2c_signin&client_id=client-1');
});

it('refuses an endpoint whose query already sets a parameter it sends', function (): void {
    $this->provider->discovery['end_session_endpoint'] = $this->provider->endSessionUrl.'?client_id=other';

    Refusals::assert(fn () => ($this->flow)()->start(), ErrorCode::DiscoveryInvalid, DiscoveryFailed::class, 'already sets client_id');
});

it('refuses to send the browser to an endpoint the SSRF guard blocks', function (): void {
    $this->provider->discovery['end_session_endpoint'] = 'https://10.0.0.5/logout';

    Refusals::assert(fn () => ($this->flow)()->start(), ErrorCode::HttpBlocked, OutboundRequestBlocked::class, 'refused to send the browser to https://10.0.0.5');
});

describe('a provider without an end_session_endpoint', function (): void {
    beforeEach(function (): void {
        unset($this->provider->discovery['end_session_endpoint']);
    });

    it('says so', function (): void {
        expect(($this->flow)()->supported())->toBeFalse();

        Refusals::assert(fn () => ($this->flow)()->start(), ErrorCode::EndpointNotSupported, EndpointNotSupported::class, 'advertises no end_session_endpoint');
    });

    it('falls back to a URL of the application', function (): void {
        expect(($this->flow)()->redirect(fallback: '/signed-out')->headers->get('Location'))->toEndWith('/signed-out');
    });
});

it('redirects to the provider when it can', function (): void {
    expect(($this->flow)()->supported())->toBeTrue()
        ->and(($this->flow)()->redirect(fallback: '/signed-out')->headers->get('Location'))->toStartWith($this->provider->endSessionUrl);
});

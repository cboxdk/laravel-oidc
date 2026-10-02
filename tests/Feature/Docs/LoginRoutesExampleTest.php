<?php

declare(strict_types=1);

use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Illuminate\Testing\TestResponse;

/**
 * Loads the routes of docs/core-concepts/login-flow.md and runs a whole login
 * through them, browser cookies included, so the documented routes keep
 * working.
 */
beforeEach(function (): void {
    $markdown = (string) file_get_contents(__DIR__.'/../../../docs/core-concepts/login-flow.md');
    expect(preg_match('/<!-- example: login-routes -->\n```php\n(.*?)```/s', $markdown, $match))->toBe(1);

    $file = (string) tempnam(sys_get_temp_dir(), 'oidc-routes-');
    file_put_contents($file, $match[1]);

    try {
        require $file;
    } finally {
        unlink($file);
    }

    $this->provider = new FakeProvider()->install();
    $this->sessionCookie = fn (TestResponse $response): string => (string) $response->getCookie((string) config('session.cookie'))?->getValue();
});

it('runs a login through the documented routes', function (): void {
    $login = $this->get('/oidc/main/login');
    $login->assertRedirect();

    $query = $this->provider->approve((string) $login->headers->get('Location'), ['groups' => ['staff']]);

    $this->withCookie((string) config('session.cookie'), ($this->sessionCookie)($login))
        ->get('/oidc/main/callback?'.http_build_query($query))
        ->assertOk()
        ->assertExactJson(['issuer' => FakeProvider::ISSUER, 'subject' => 'user-1', 'tenant' => null, 'groups' => ['staff'], 'has_refresh_token' => true]);
});

it('tells a person of another Google Workspace domain that their organisation cannot sign in', function (): void {
    $google = new FakeProvider('https://accounts.google.com')->install();
    $google->clients = ['google-client' => ['secret' => 'google-secret']];
    $google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];

    $login = $this->get('/oidc/workspace/login');
    $query = $google->approve((string) $login->headers->get('Location'), ['hd' => 'example.org']);

    $this->withCookie((string) config('session.cookie'), ($this->sessionCookie)($login))
        ->get('/oidc/workspace/callback?'.http_build_query($query))
        ->assertRedirect('/')
        ->assertSessionHas('status', 'Your organisation cannot sign in here.');
});

it('refuses a login whose ID token fails verification', function (): void {
    $login = $this->get('/oidc/main/login');
    $query = $this->provider->approve((string) $login->headers->get('Location'), ['nonce' => 'another-login']);

    $this->withCookie((string) config('session.cookie'), ($this->sessionCookie)($login))
        ->get('/oidc/main/callback?'.http_build_query($query))
        ->assertRedirect('/')
        ->assertSessionHas('status', 'Sign-in failed. Please try again.');
});

it('refuses a callback from another browser', function (): void {
    $login = $this->get('/oidc/main/login');
    $query = $this->provider->approve((string) $login->headers->get('Location'));

    // Another browser has another session.
    $this->flushSession();

    $this->get('/oidc/main/callback?'.http_build_query($query))
        ->assertRedirect('/')
        ->assertSessionHas('status', 'Sign-in failed. Please try again.');

    expect($this->provider->tokenRequests)->toBe([]);
});

it('starts an interactive login when a silent one needs the person', function (): void {
    $login = $this->get('/oidc/main/login');
    $query = $this->provider->deny((string) $login->headers->get('Location'), 'login_required');

    $retry = $this->withCookie((string) config('session.cookie'), ($this->sessionCookie)($login))
        ->get('/oidc/main/callback?'.http_build_query($query));

    $retry->assertRedirect();
    expect($retry->headers->get('Location'))->toStartWith(FakeProvider::AUTHORIZATION_URL.'?');
});

it('answers a cancelled login', function (): void {
    $login = $this->get('/oidc/main/login');
    $query = $this->provider->deny((string) $login->headers->get('Location'));

    $this->withCookie((string) config('session.cookie'), ($this->sessionCookie)($login))
        ->get('/oidc/main/callback?'.http_build_query($query))
        ->assertRedirect('/')
        ->assertSessionHas('status', 'Sign-in was cancelled.');
});

it('only routes configured connections', function (): void {
    $this->get('/oidc/unknown/login')->assertNotFound();
    expect(resolve(AuthorizationFlow::class))->toBeInstanceOf(AuthorizationFlow::class);
});

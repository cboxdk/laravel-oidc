<?php

declare(strict_types=1);

use Cbox\Oidc\Events\BackChannelLogoutReceived;
use Cbox\Oidc\Routing\BackChannelLogoutController;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
use Illuminate\Routing\Route as RoutingRoute;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Route;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->route = Route::oidcBackChannelLogout();
    $this->post = fn (array $form, string $uri = '/oidc/main/backchannel-logout') => $this->post($uri, $form, ['Accept' => 'application/json']);
});

it('registers a POST route named oidc.backchannel-logout without CSRF verification', function (): void {
    expect($this->route)->toBeInstanceOf(RoutingRoute::class)
        ->and($this->route->uri())->toBe('oidc/{connection}/backchannel-logout')
        ->and($this->route->methods())->toBe(['POST'])
        ->and($this->route->getName())->toBe('oidc.backchannel-logout')
        ->and($this->route->excludedMiddleware())->toContain(ValidateCsrfToken::class);
});

it('dispatches the verified logout token and answers 200', function (): void {
    Event::fake([BackChannelLogoutReceived::class]);

    $response = ($this->post)(['logout_token' => $this->provider->logoutToken(['jti' => 'jti-1'])]);

    $response->assertOk();
    expect($response->getContent())->toBe('')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store');

    Event::assertDispatched(BackChannelLogoutReceived::class, fn (BackChannelLogoutReceived $event): bool => $event->token->jti === 'jti-1'
        && $event->token->connection === 'main'
        && $event->token->sessionId === 'session-1'
        && $event->token->subject === 'user-1');
});

it('serves one connection on a route of its own', function (): void {
    Event::fake([BackChannelLogoutReceived::class]);
    $route = Route::oidcBackChannelLogout('identity/logout', 'main');

    expect($route->getName())->toBe('oidc.backchannel-logout.main');

    ($this->post)(['logout_token' => $this->provider->logoutToken()], '/identity/logout')->assertOk();

    Event::assertDispatched(BackChannelLogoutReceived::class, fn (BackChannelLogoutReceived $event): bool => $event->token->connection === 'main');
});

it('answers 400 without a logout token in the form body', function (array $form, string $query): void {
    Event::fake([BackChannelLogoutReceived::class]);

    ($this->post)($form, '/oidc/main/backchannel-logout'.$query)
        ->assertStatus(400)
        ->assertHeader('Cache-Control', 'no-store, private')
        ->assertExactJson(['error' => 'invalid_request', 'error_description' => 'The request has no logout_token in its form body.']);

    Event::assertNotDispatched(BackChannelLogoutReceived::class);
})->with([
    'no parameter' => [[], ''],
    'an empty token' => [['logout_token' => ''], ''],
    'a list' => [['logout_token' => ['a', 'b']], ''],
    'only in the query' => [[], '?logout_token=abc.def.ghi'],
]);

it('answers 400 for a refused token and logs why', function (): void {
    Event::fake([BackChannelLogoutReceived::class]);
    Log::spy();

    ($this->post)(['logout_token' => $this->provider->logoutToken(['nonce' => 'n'])])
        ->assertStatus(400)
        ->assertExactJson(['error' => 'invalid_request', 'error_description' => 'The logout token was refused (oidc_logout_token_invalid).']);

    Event::assertNotDispatched(BackChannelLogoutReceived::class);
    Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message, array $context): bool => str_contains($message, 'has a nonce')
        && $context === ['code' => 'oidc_logout_token_invalid', 'connection' => 'main']);
});

it('answers 400 to a replay', function (): void {
    Event::fake([BackChannelLogoutReceived::class]);
    $token = $this->provider->logoutToken();

    ($this->post)(['logout_token' => $token])->assertOk();
    ($this->post)(['logout_token' => $token])->assertStatus(400)->assertJsonPath('error_description', 'The logout token was refused (oidc_logout_token_replayed).');

    Event::assertDispatchedTimes(BackChannelLogoutReceived::class, 1);
});

it('answers 404 for a connection that is not configured', function (): void {
    ($this->post)(['logout_token' => $this->provider->logoutToken()], '/oidc/unknown/backchannel-logout')->assertNotFound();
});

it('answers 503 when the provider\'s keys cannot be loaded, so the provider retries', function (): void {
    Log::spy();
    $this->provider->jwksStatus = 503;

    ($this->post)(['logout_token' => $this->provider->logoutToken()])
        ->assertStatus(503)
        ->assertJsonPath('error', 'temporarily_unavailable');

    Log::shouldHaveReceived('error')->once();
});

it('answers 400 with a warning to a token whose kid the key set lacks, also after a refetch', function (): void {
    Log::spy();
    $forger = FakeProvider::rsaKey('forger', values: ['kid' => 'unknown-kid']);

    ($this->post)(['logout_token' => $this->provider->logoutToken(key: $forger)])
        ->assertStatus(400)
        ->assertExactJson(['error' => 'invalid_request', 'error_description' => 'The logout token was refused (oidc_signing_key_not_found).']);

    Log::shouldHaveReceived('warning')->once()->withArgs(fn (string $message, array $context): bool => str_contains($message, 'also after refetching the key set')
        && $context === ['code' => 'oidc_signing_key_not_found', 'connection' => 'main']);
    Log::shouldNotHaveReceived('error');
});

it('answers 503 with a warning to an unknown kid while a refetch is held back, so a rotation can be retried', function (): void {
    Log::spy();
    $forger = FakeProvider::rsaKey('forger', values: ['kid' => 'unknown-kid']);

    ($this->post)(['logout_token' => $this->provider->logoutToken(key: $forger)])->assertStatus(400);
    ($this->post)(['logout_token' => $this->provider->logoutToken(key: $forger)])
        ->assertStatus(503)
        ->assertExactJson(['error' => 'temporarily_unavailable', 'error_description' => 'The logout token could not be verified now (oidc_signing_key_not_found).']);

    expect($this->provider->jwksRequests)->toBe(2);
    Log::shouldHaveReceived('warning')->twice();
    Log::shouldNotHaveReceived('error');
});

it('answers 400 with a warning to a token whose key may not verify it', function (): void {
    Log::spy();
    // ES256, naming the provider's RSA key.
    $token = $this->provider->logoutToken(algorithm: SigningAlgorithm::ES256, header: ['kid' => 'rsa-1'], key: FakeProvider::ecKey('forger'));

    ($this->post)(['logout_token' => $token])
        ->assertStatus(400)
        ->assertJsonPath('error_description', 'The logout token was refused (oidc_signing_key_unsuitable).');

    Log::shouldHaveReceived('warning')->once();
    Log::shouldNotHaveReceived('error');
});

it('accepts only POST', function (): void {
    $this->get('/oidc/main/backchannel-logout?logout_token='.$this->provider->logoutToken())->assertStatus(405);
});

it('gives the jti back when a listener fails, so the provider can deliver the token again', function (): void {
    $token = $this->provider->logoutToken();
    $state = new ArrayObject(['fail' => true, 'handled' => 0]);

    Event::listen(BackChannelLogoutReceived::class, function () use ($state): void {
        if ($state['fail'] === true) {
            throw new RuntimeException('session store down');
        }

        $state['handled']++;
    });

    ($this->post)(['logout_token' => $token])->assertStatus(500);

    $state['fail'] = false;

    ($this->post)(['logout_token' => $token])->assertOk();
    expect($state['handled'])->toBe(1);
});

it('uses the controller by its class', function (): void {
    expect($this->route->getActionName())->toBe(BackChannelLogoutController::class);
});

<?php

declare(strict_types=1);

use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Events\BackChannelLogoutReceived;
use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidArgument;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Testing\OidcFake;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use PHPUnit\Framework\ExpectationFailedException;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->fake = Oidc::fake();
});

it('replaces the client behind the facade and the contract', function (): void {
    expect($this->fake)->toBeInstanceOf(OidcFake::class)
        ->and(resolve(OidcClient::class))->toBe($this->fake)
        ->and(Oidc::getFacadeRoot())->toBe($this->fake);
});

it('starts a login without calling a provider', function (): void {
    $redirect = Oidc::redirect(options: new AuthorizationOptions(prompt: Prompt::Login, loginHint: 'ada@example.com', scopes: ['offline_access']));
    parse_str((string) parse_url($redirect->getTargetUrl(), PHP_URL_QUERY), $query);

    expect($redirect->getTargetUrl())->toStartWith(OidcFake::AUTHORIZATION_URL.'?')
        ->and($query)->toMatchArray([
            'connection' => 'main',
            'client_id' => 'client-1',
            'redirect_uri' => 'https://app.example.test/oidc/callback',
            'scope' => 'openid profile email offline_access',
            'login_hint' => 'ada@example.com',
            'prompt' => 'login',
        ])
        ->and($query['state'])->toMatch('/^[A-Za-z0-9_-]{43}$/');

    Http::assertNothingSent();
    $this->fake->assertRedirected();
    $this->fake->assertRedirected('main', fn (AuthorizationOptions $options): bool => $options->loginHint === 'ada@example.com');
    $this->fake->assertNotRedirected('workspace');
});

it('returns a queued sign-in with the claims of a verified login', function (): void {
    $request = Oidc::start();
    $this->fake->signIn('ada', ['email' => 'ada@example.com', 'groups' => ['staff', 'admin'], 'amr' => ['pwd', 'mfa'], 'acr' => 'urn:mfa']);

    $result = Oidc::callback();
    $claims = $result->claims;

    expect($result->connection)->toBe('main')
        ->and($result->transaction->state)->toBe($request->state)
        ->and($claims->issuer)->toBe('https://idp.example.test')
        ->and($claims->subject)->toBe('ada')
        ->and($claims->audience)->toBe(['client-1'])
        ->and($claims->email())->toBe('ada@example.com')
        ->and($claims->groups)->toBe(['staff', 'admin'])
        ->and($claims->authenticationMethods)->toBe(['pwd', 'mfa'])
        ->and($claims->authenticationContext)->toBe('urn:mfa')
        ->and($claims->authTime?->getTimestamp())->toBe(now()->getTimestamp())
        ->and($claims->issuedAt->getTimestamp())->toBe(now()->getTimestamp())
        ->and($claims->expiresAt->getTimestamp())->toBe(now()->getTimestamp() + 3600)
        ->and($claims->sessionId)->toStartWith('fake-session-')
        ->and($claims->claim('nonce'))->toBe($result->transaction->nonce)
        ->and($result->tokens->tokenType)->toBe('Bearer')
        ->and($result->tokens->accessToken)->toStartWith('fake-access-token-')
        ->and($result->tokens->refreshToken)->toStartWith('fake-refresh-token-')
        ->and($result->tokens->scopes)->toBe(['openid', 'profile', 'email']);

    $this->fake->assertSignedIn();
    $this->fake->assertSignedIn('ada', 'main');
    $this->fake->assertNoPendingSignIns();
    expect($this->fake->signIns())->toBe([$result]);
});

it('takes the queued outcomes of a connection in order', function (): void {
    $this->fake->signIn('first')->signIn('second')->signIn('google-person', ['hd' => 'example.com'], 'workspace');

    expect(Oidc::callback()->claims->subject)->toBe('first')
        ->and(Oidc::connection('workspace')->callback()->claims)
        ->subject->toBe('google-person')
        ->issuer->toBe('https://accounts.google.com')
        ->tenant->toBe('example.com')
        ->groups->toBeNull()
        ->and(Oidc::callback()->claims->subject)->toBe('second');

    expect($this->fake->signIns('workspace'))->toHaveCount(1);
});

it('fills the tenant into an Entra issuer template', function (): void {
    config(['oidc.connections.entra' => ConnectionFixtures::entraMultiTenant()]);

    $this->fake->signIn('person', ['tid' => '11111111-1111-1111-1111-111111111111'], 'entra')->signIn('other', connection: 'entra');

    expect(Oidc::callback('entra')->claims)
        ->issuer->toBe('https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0')
        ->tenant->toBe('11111111-1111-1111-1111-111111111111')
        ->audience->toBe(['00000000-0000-0000-0000-000000000001'])
        ->and(Oidc::callback('entra')->claims->issuer)->toBe('https://login.microsoftonline.com/'.OidcFake::TENANT_ID.'/v2.0');
});

it('reads groups from userinfo when the connection does', function (): void {
    config(['oidc.connections.main.groups' => ['source' => 'userinfo', 'claim' => 'roles']]);
    $this->fake->withUserInfo(['roles' => ['editor'], 'name' => 'Ada'])->signIn('ada', ['roles' => ['ignored']]);

    $result = Oidc::callback();

    expect($result->claims->groups)->toBe(['editor'])
        ->and($result->userInfo?->groups)->toBe(['editor'])
        ->and($result->userInfo?->name())->toBe('Ada');
});

it('throws the failures it was told to', function (): void {
    $this->fake->denySignIn('login_required')
        ->denySignIn()
        ->failSignIn(TenantRejected::notAllowed('main', 'hd', 'example.org'));

    try {
        Oidc::callback();
        $this->fail('Expected AuthorizationDenied.');
    } catch (AuthorizationDenied $denied) {
        expect($denied->error())->toBe('login_required')
            ->and($denied->interactionRequired())->toBeTrue();
    }

    expect(fn () => Oidc::callback())->toThrow(AuthorizationDenied::class, 'access_denied')
        ->and(fn () => Oidc::callback())->toThrow(TenantRejected::class, '[oidc_tenant_not_allowed]');

    $this->fake->assertNotSignedIn();
    $this->fake->assertNoPendingSignIns();
});

it('says what to do when a callback runs with nothing queued', function (): void {
    expect(fn () => Oidc::callback())->toThrow(LogicException::class, 'Oidc::fake() has no sign-in queued for connection "main". Call signIn(), denySignIn() or failSignIn()');
});

it('knows the configured connections', function (): void {
    expect(fn () => Oidc::redirect('nope'))->toThrow(UnknownConnection::class, 'Use one of main, workspace')
        ->and(fn () => $this->fake->signIn(connection: 'nope'))->toThrow(UnknownConnection::class)
        ->and(fn () => $this->fake->signIn(''))->toThrow(InvalidArgument::class, '[oidc_argument_invalid]');
});

it('works without any configuration', function (): void {
    config(['oidc' => null]);
    $this->fake->signIn('anyone', connection: 'anything');

    expect(Oidc::callback('anything')->claims)
        ->issuer->toBe(OidcFake::ISSUER)
        ->audience->toBe(['fake-client'])
        ->and(Oidc::connection()->name)->toBe('main');
});

it('refreshes with rotation, and refuses a used or revoked refresh token', function (): void {
    $this->fake->signIn('ada', ['groups' => ['staff']]);
    $login = Oidc::callback();
    $this->travel(10)->minutes();

    $renewed = Oidc::refresh($login->claims, (string) $login->tokens->refreshToken);

    expect($renewed->rotated)->toBeTrue()
        ->and($renewed->idTokenRenewed)->toBeTrue()
        ->and($renewed->refreshToken)->not->toBe($login->tokens->refreshToken)
        ->and($renewed->claims->subject)->toBe('ada')
        ->and($renewed->claims->groups)->toBe(['staff'])
        ->and($renewed->claims->sessionId)->toBe($login->claims->sessionId)
        ->and($renewed->claims->authTime)->toEqual($login->claims->authTime)
        ->and($renewed->claims->issuedAt->getTimestamp())->toBe(now()->getTimestamp());

    $this->fake->assertRefreshed('main');

    try {
        Oidc::refresh($login->claims, (string) $login->tokens->refreshToken);
        $this->fail('Expected TokenRequestRejected.');
    } catch (TokenRequestRejected $rejected) {
        expect($rejected->refreshTokenInvalid())->toBeTrue()
            ->and($rejected->grant())->toBe('refresh_token');
    }

    Oidc::revoke($renewed->refreshToken);

    expect(fn () => Oidc::refresh($renewed->claims, $renewed->refreshToken))->toThrow(TokenRequestRejected::class, 'invalid_grant');
    $this->fake->assertRevoked($renewed->refreshToken);
    $this->fake->assertRevoked(connection: 'main');
});

it('fails a refresh it was told to fail', function (): void {
    $this->fake->signIn();
    $login = Oidc::callback();
    $this->fake->failRefresh(TokenRequestRejected::byProvider('main', 'https://idp.example.test/token', 503, 'temporarily_unavailable', 'refresh_token'));

    expect(fn () => Oidc::refresh($login->claims, (string) $login->tokens->refreshToken))->toThrow(TokenRequestRejected::class, 'temporarily_unavailable')
        ->and(Oidc::refresh($login->claims, (string) $login->tokens->refreshToken)->rotated)->toBeTrue();
});

it('returns userinfo for the signed-in person', function (): void {
    $this->fake->signIn('ada', ['email' => 'ada@example.com'])->withUserInfo(['picture' => 'https://example.com/ada.png']);
    $login = Oidc::callback();

    $info = Oidc::userInfo($login->claims, $login->tokens->accessToken);

    expect($info->subject)->toBe('ada')
        ->and($info->all())->toBe(['sub' => 'ada', 'email' => 'ada@example.com', 'picture' => 'https://example.com/ada.png'])
        ->and($info->groups)->toBeNull();
});

it('logs out to where the provider would send the browser back', function (): void {
    $this->fake->signIn();
    $login = Oidc::callback();

    expect(Oidc::logout(options: new LogoutOptions(idTokenHint: $login->tokens->idToken), fallback: '/bye')->getTargetUrl())->toEndWith('/bye');

    config(['oidc.connections.main.post_logout_redirect_uri' => 'https://app.example.test/signed-out']);

    expect(Oidc::logout()->getTargetUrl())->toBe('https://app.example.test/signed-out')
        ->and(Oidc::logout(options: new LogoutOptions(postLogoutRedirectUri: 'https://app.example.test/elsewhere'))->getTargetUrl())->toBe('https://app.example.test/elsewhere');

    $this->fake->assertLoggedOut();
    $this->fake->assertLoggedOut('main', fn (LogoutOptions $options): bool => $options->idTokenHint === $login->tokens->idToken);
    $this->fake->assertNotLoggedOut('workspace');
});

it('issues ID tokens that no verifier accepts', function (): void {
    new FakeProvider()->install();
    $this->fake->signIn();
    $login = Oidc::callback();

    [$header] = explode('.', (string) $login->tokens->idToken);

    expect(json_decode(base64_decode(strtr($header, '-_', '+/')), true))->toBe(['alg' => 'none', 'typ' => 'JWT']);

    try {
        resolve(IdTokenVerifier::class)->verify('main', (string) $login->tokens->idToken, IdTokenExpectations::forLogin($login->transaction));
        $this->fail('Expected TokenRejected.');
    } catch (TokenRejected $rejected) {
        expect($rejected->errorCode())->toBe(ErrorCode::TokenMalformed);
    }
});

it('dispatches the back-channel logout event to your listeners', function (): void {
    Event::fake([BackChannelLogoutReceived::class]);

    $token = $this->fake->backChannelLogout('ada', 'session-9');

    expect($token->subject)->toBe('ada')
        ->and($token->sessionId)->toBe('session-9')
        ->and($token->issuer)->toBe('https://idp.example.test')
        ->and($token->endsOneSession())->toBeTrue();

    Event::assertDispatched(BackChannelLogoutReceived::class, fn (BackChannelLogoutReceived $event): bool => $event->token === $token);

    expect($this->fake->backChannelLogout(sessionId: null)->endsOneSession())->toBeFalse()
        ->and(fn () => $this->fake->backChannelLogout(null))->toThrow(InvalidArgument::class);
});

it('fails each assertion with a message that says what happened', function (Closure $assertion, string $message): void {
    expect(fn () => $assertion($this->fake))->toThrow(ExpectationFailedException::class, $message);
})->with([
    'redirected' => [fn (OidcFake $fake) => $fake->assertRedirected(), 'No login on any connection was started.'],
    'redirected with callback' => [function (OidcFake $fake): void {
        Oidc::redirect();
        $fake->assertRedirected('main', fn (): bool => false);
    }, 'No login on connection "main" was started that matches the callback.'],
    'not redirected' => [function (OidcFake $fake): void {
        Oidc::redirect();
        $fake->assertNotRedirected();
    }, '1 login(s) on any connection were started.'],
    'signed in' => [fn (OidcFake $fake) => $fake->assertSignedIn('ada'), 'Nobody with subject "ada" signed in on any connection.'],
    'not signed in' => [function (OidcFake $fake): void {
        $fake->signIn();
        Oidc::callback();
        $fake->assertNotSignedIn('main');
    }, '1 sign-in(s) on connection "main" succeeded.'],
    'pending' => [fn (OidcFake $fake) => $fake->signIn()->assertNoPendingSignIns(), '1 queued sign-in(s) were never used by a callback.'],
    'refreshed' => [fn (OidcFake $fake) => $fake->assertRefreshed(), 'No tokens on any connection were refreshed.'],
    'not refreshed' => [function (OidcFake $fake): void {
        $fake->signIn();
        $login = Oidc::callback();
        Oidc::refresh($login->claims, (string) $login->tokens->refreshToken);
        $fake->assertNotRefreshed();
    }, '1 refresh(es) on any connection happened.'],
    'logged out' => [fn (OidcFake $fake) => $fake->assertLoggedOut('main'), 'No logout on connection "main" happened.'],
    'not logged out' => [function (OidcFake $fake): void {
        Oidc::logout();
        $fake->assertNotLoggedOut();
    }, '1 logout(s) on any connection happened.'],
    'revoked' => [fn (OidcFake $fake) => $fake->assertRevoked('token-1'), 'No such token on any connection was revoked.'],
    'not revoked' => [function (OidcFake $fake): void {
        Oidc::revoke('token-1', TokenTypeHint::AccessToken);
        $fake->assertNotRevoked();
    }, '1 token(s) on any connection were revoked.'],
]);

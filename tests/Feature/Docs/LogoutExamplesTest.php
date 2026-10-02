<?php

declare(strict_types=1);

use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Illuminate\Http\Client\Factory;

/**
 * Loads the route files of docs/core-concepts/logout.md and runs them, so the
 * documented logout and back-channel logout keep working.
 */
function loadLogoutExample(string $name): void
{
    $markdown = (string) file_get_contents(__DIR__.'/../../../docs/core-concepts/logout.md');
    expect(preg_match('/<!-- example: '.$name.' -->\n```php\n(.*?)```/s', $markdown, $match))->toBe(1);

    $file = (string) tempnam(sys_get_temp_dir(), 'oidc-logout-');
    file_put_contents($file, $match[1]);

    try {
        require $file;
    } finally {
        unlink($file);
    }
}

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->signedIn = fn (array $claims = []): VerifiedClaims => resolve(IdTokenVerifier::class)->verify('main', $this->provider->idToken($claims), new IdTokenExpectations('nonce-1'));
});

describe('the logout route', function (): void {
    beforeEach(function (): void {
        loadLogoutExample('logout-route');
    });

    it('ends the session, revokes the refresh token and logs out at the provider', function (): void {
        $idToken = $this->provider->idToken();
        $refreshToken = $this->provider->issueRefreshToken();

        $response = $this->withSession(['oidc.id_token' => $idToken, 'oidc.refresh_token' => $refreshToken, 'user' => 'ada'])->post('/logout');

        $response->assertRedirect();
        parse_str((string) parse_url((string) $response->headers->get('Location'), PHP_URL_QUERY), $query);

        expect((string) $response->headers->get('Location'))->toStartWith($this->provider->endSessionUrl.'?')
            ->and($query)->toBe(['client_id' => 'client-1', 'id_token_hint' => $idToken])
            ->and($this->provider->refreshTokenLive($refreshToken))->toBeFalse()
            ->and(session()->has('user'))->toBeFalse();
    });

    it('still logs out when the provider cannot revoke or has no logout endpoint', function (): void {
        unset($this->provider->discovery['end_session_endpoint']);
        $this->provider->revocationResponse = fn (): mixed => Factory::response('', 503);

        $this->withSession(['oidc.refresh_token' => 'refresh-1', 'user' => 'ada'])->post('/logout')->assertRedirect('/');

        expect(session()->has('user'))->toBeFalse();
    });
});

describe('back-channel logout', function (): void {
    beforeEach(function (): void {
        loadLogoutExample('backchannel-logout');
    });

    it('signs out the session the provider ended, and no other', function (): void {
        $this->post('/oidc/main/backchannel-logout', ['logout_token' => $this->provider->logoutToken(['sid' => 'session-1'])])->assertOk();

        $this->withSession(['oidc.claims' => ($this->signedIn)(['sid' => 'session-1'])])->get('/account')->assertRedirect('/login');
        $this->withSession(['oidc.claims' => ($this->signedIn)(['sid' => 'session-2'])])->get('/account')->assertOk()->assertExactJson(['subject' => 'user-1']);
    });

    it('signs out every earlier session of a subject when the token names no sid', function (): void {
        $earlier = ($this->signedIn)(['sid' => 'session-3']);
        $this->travel(5)->seconds();

        $this->post('/oidc/main/backchannel-logout', ['logout_token' => $this->provider->logoutToken(['sid' => null])])->assertOk();
        $this->withSession(['oidc.claims' => $earlier])->get('/account')->assertRedirect('/login');

        $this->travel(5)->seconds();
        $this->withSession(['oidc.claims' => ($this->signedIn)(['sid' => 'session-4'])])->get('/account')->assertOk();
    });

    it('refuses a logout token that is not one', function (): void {
        $this->post('/oidc/main/backchannel-logout', ['logout_token' => $this->provider->idToken(['sid' => 'session-1'])])->assertStatus(400);

        $this->withSession(['oidc.claims' => ($this->signedIn)(['sid' => 'session-1'])])->get('/account')->assertOk();
    });

    it('sends a visitor without a session to the login', function (): void {
        $this->get('/account')->assertRedirect('/login');
    });
});

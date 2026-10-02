<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\UserInfoRejected;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Cbox\Oidc\UserInfo\UserInfo;
use Cbox\Oidc\UserInfo\UserInfoEndpoint;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->provider = new FakeProvider()->install();
    $this->claims = fn (): VerifiedClaims => resolve(IdTokenVerifier::class)->verify('main', $this->provider->idToken(), new IdTokenExpectations('nonce-1'));
    $this->accessToken = $this->provider->issueAccessToken(['email' => 'ada@example.com', 'email_verified' => true, 'name' => 'Ada Lovelace', 'groups' => ['staff', 'staff', 'admins']]);
    $this->fetch = fn (?string $accessToken = null): UserInfo => resolve(UserInfoEndpoint::class)->fetch(($this->claims)(), $accessToken ?? $this->accessToken);
    $this->respond = function (string $body, int $status = 200, array $headers = ['Content-Type' => 'application/json']): void {
        $this->provider->userInfoResponse = fn (): mixed => Factory::response($body, $status, $headers);
    };
});

it('returns the claims of the person the access token belongs to', function (): void {
    $info = ($this->fetch)();

    expect($info->connection)->toBe('main')
        ->and($info->subject)->toBe('user-1')
        ->and($info->email())->toBe('ada@example.com')
        ->and($info->emailVerified())->toBeTrue()
        ->and($info->name())->toBe('Ada Lovelace')
        ->and($info->groups)->toBeNull()
        ->and($info->has('groups'))->toBeTrue()
        ->and($info->claim('missing', 'default'))->toBe('default')
        ->and($info->all())->toHaveKeys(['sub', 'email', 'name', 'groups'])
        ->and($this->provider->userInfoRequests)->toBe(['Bearer '.$this->accessToken]);
});

it('reads the groups when the connection takes them from userinfo', function (): void {
    Refusals::useConnection('main', ConnectionFixtures::minimal(['groups' => ['source' => 'userinfo']]));

    expect(($this->fetch)()->groups)->toBe(['staff', 'admins']);
});

it('reads no groups as an empty list, and refuses groups that are not a list of strings', function (): void {
    Refusals::useConnection('main', ConnectionFixtures::minimal(['groups' => ['source' => 'userinfo', 'claim' => 'roles']]));

    expect(($this->fetch)()->groups)->toBe([]);

    ($this->respond)('{"sub":"user-1","roles":"admin"}');

    Refusals::assert(fn () => ($this->fetch)(), ErrorCode::ProviderResponseInvalid, InvalidProviderResponse::class, 'its roles claim is not a list of strings');
});

it('refuses the claims of another person', function (string $body): void {
    ($this->respond)($body);

    Refusals::assert(fn () => ($this->fetch)(), ErrorCode::UserInfoSubjectMismatch, UserInfoRejected::class, 'names another sub than the ID token');
})->with([
    'another sub' => ['{"sub":"user-2","email":"eve@example.com"}'],
    'no sub' => ['{"email":"ada@example.com"}'],
    'a sub that is not a string' => ['{"sub":1}'],
    'a sub in another case' => ['{"sub":"USER-1"}'],
]);

it('says why the provider refused the access token', function (int $status, ?string $challenge, ?string $error, string $fix): void {
    ($this->respond)('', $status, $challenge === null ? [] : ['WWW-Authenticate' => $challenge]);

    $exception = Refusals::assert(fn () => ($this->fetch)(), ErrorCode::UserInfoRejected, UserInfoRejected::class, sprintf('HTTP %d', $status));
    assert($exception instanceof UserInfoRejected);

    expect($exception->error())->toBe($error)
        ->and($exception->fix())->toContain($fix);
})->with([
    'an expired token' => [401, 'Bearer error="invalid_token", error_description="expired"', 'invalid_token', 'Refresh it'],
    'a missing scope' => [403, 'Bearer realm="idp", error="insufficient_scope"', 'insufficient_scope', 'oidc.connections.main.scopes'],
    'no challenge' => [401, null, null, 'Refresh it'],
    'a challenge with markup' => [401, 'Bearer error="<script>"', 'unrecognized_error', 'Refresh it'],
]);

it('refuses an access token the provider does not know', function (): void {
    Refusals::assert(fn () => ($this->fetch)('unknown-token'), ErrorCode::UserInfoRejected, UserInfoRejected::class, 'the error invalid_token');
});

it('reports a temporary failure as retryable', function (int $status): void {
    ($this->respond)('', $status);

    Refusals::assert(fn () => ($this->fetch)(), ErrorCode::ProviderUnavailable, ProviderUnavailable::class);
})->with([429, 500, 503]);

it('refuses a response that is not plain JSON userinfo', function (string $body, int $status, array $headers, string $message): void {
    ($this->respond)($body, $status, $headers);

    Refusals::assert(fn () => ($this->fetch)(), ErrorCode::ProviderResponseInvalid, InvalidProviderResponse::class, $message);
})->with([
    'a redirect' => ['', 302, ['Location' => 'https://idp.example.test/login'], 'HTTP 302'],
    'not found' => ['', 404, [], 'HTTP 404'],
    'a signed response' => ['eyJhbGciOiJSUzI1NiJ9.e30.c2ln', 200, ['Content-Type' => 'application/jwt'], 'application/jwt'],
    'HTML' => ['<html></html>', 200, ['Content-Type' => 'text/html'], 'not a JSON object with unique keys'],
    'a list' => ['[{"sub":"user-1"}]', 200, ['Content-Type' => 'application/json'], 'not a JSON object with unique keys'],
    'a duplicate sub' => ['{"sub":"user-2","sub":"user-1"}', 200, ['Content-Type' => 'application/json'], 'not a JSON object with unique keys'],
]);

it('needs the provider to advertise the endpoint', function (): void {
    unset($this->provider->discovery['userinfo_endpoint']);

    expect(resolve(UserInfoEndpoint::class)->supported())->toBeFalse();

    $exception = Refusals::assert(fn () => ($this->fetch)(), ErrorCode::EndpointNotSupported, EndpointNotSupported::class, 'advertises no userinfo_endpoint');
    assert($exception instanceof EndpointNotSupported);

    expect($exception->endpoint())->toBe('userinfo_endpoint')
        ->and($this->provider->userInfoRequests)->toBe([]);
});

it('says when the endpoint is advertised', function (): void {
    expect(resolve(UserInfoEndpoint::class)->supported())->toBeTrue();
});

it('sends the access token only through the SSRF guard', function (): void {
    $this->provider->discovery['userinfo_endpoint'] = 'https://internal.example.test/userinfo';

    Refusals::assert(fn () => ($this->fetch)(), ErrorCode::HttpBlocked, OutboundRequestBlocked::class);
});

describe('a login of a connection that reads groups from userinfo', function (): void {
    beforeEach(function (): void {
        Refusals::useConnection('main', ConnectionFixtures::minimal(['groups' => ['source' => 'userinfo']]));
        $this->callback = function (array $claims = []): mixed {
            $flow = resolve(AuthorizationFlow::class);
            $request = $flow->start();

            return $flow->callback(Request::create('/oidc/callback', 'GET', $this->provider->approve($request->url, $claims)));
        };
    });

    it('fills the groups of the claims from userinfo', function (): void {
        $this->provider->userInfoClaims = ['groups' => ['editors']];
        $result = ($this->callback)(['groups' => ['ignored']]);

        expect($result->claims->groups)->toBe(['editors'])
            ->and($result->userInfo?->groups)->toBe(['editors'])
            ->and($result->userInfo?->subject)->toBe('user-1');
    });

    it('fails the login when userinfo names another person', function (): void {
        $this->provider->userInfoClaims = ['sub' => 'user-2'];

        Refusals::assert(fn () => ($this->callback)(), ErrorCode::UserInfoSubjectMismatch, UserInfoRejected::class);
    });
});

it('does not call userinfo during a login of a connection that reads groups from the ID token', function (): void {
    $flow = resolve(AuthorizationFlow::class);
    $request = $flow->start();
    $result = $flow->callback(Request::create('/oidc/callback', 'GET', $this->provider->approve($request->url, ['groups' => ['staff']])));

    expect($result->userInfo)->toBeNull()
        ->and($result->claims->groups)->toBe(['staff'])
        ->and($this->provider->userInfoRequests)->toBe([]);
});

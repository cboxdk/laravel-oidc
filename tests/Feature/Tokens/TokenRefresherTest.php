<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidArgument;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Flow\AuthorizationFlow;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\RefreshResult;
use Cbox\Oidc\Tokens\TokenRefresher;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Request;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->now = now()->getTimestamp();
    $this->provider = new FakeProvider()->install();
    $this->login = function (array $claims = [], string $connection = 'main', ?FakeProvider $provider = null): VerifiedClaims {
        $provider ??= $this->provider;
        $token = $provider->idToken(array_replace(['auth_time' => $this->now - 100], $claims));

        $nonce = array_key_exists('nonce', $claims) ? $claims['nonce'] : 'nonce-1';

        return resolve(IdTokenVerifier::class)->verify($connection, $token, new IdTokenExpectations(is_string($nonce) ? $nonce : null));
    };
    $this->original = ($this->login)();
    $this->refreshToken = $this->provider->issueRefreshToken($this->original->claims);
    $this->refresh = fn (?VerifiedClaims $original = null, ?string $refreshToken = null, ?array $scopes = null): RefreshResult => resolve(TokenRefresher::class)->refresh($original ?? $this->original, $refreshToken ?? $this->refreshToken, $scopes);
});

describe('a refresh the provider accepts', function (): void {
    it('returns new tokens and the verified claims of the new ID token', function (): void {
        $result = ($this->refresh)();

        expect($result->tokens->accessToken)->toMatch('/^[0-9a-f]{32}$/')
            ->and($result->tokens->expiresAt?->getTimestamp())->toBe($this->now + 3600)
            ->and($result->idTokenRenewed)->toBeTrue()
            ->and($result->claims)->not->toBe($this->original)
            ->and($result->claims->subject)->toBe('user-1')
            ->and($result->claims->issuer)->toBe(FakeProvider::ISSUER)
            ->and($result->claims->authTime?->getTimestamp())->toBe($this->now - 100)
            ->and($result->claims->issuedAt->getTimestamp())->toBe($this->now);

        $request = $this->provider->tokenRequests[0];

        expect($request['form'])->toBe(['grant_type' => 'refresh_token', 'refresh_token' => $this->refreshToken])
            ->and($request['authorization'])->toBe('Basic '.base64_encode('client-1:secret-1'));
    });

    it('keeps the rotated refresh token and retires the old one', function (): void {
        $result = ($this->refresh)();

        expect($result->rotated)->toBeTrue()
            ->and($result->refreshToken)->not->toBe($this->refreshToken)
            ->and($result->refreshToken)->toBe($result->tokens->refreshToken)
            ->and($this->provider->refreshTokenLive($this->refreshToken))->toBeFalse()
            ->and($this->provider->refreshTokenLive($result->refreshToken))->toBeTrue();

        // The rotated token works for the next refresh.
        expect(($this->refresh)(refreshToken: $result->refreshToken)->claims->subject)->toBe('user-1');
    });

    it('keeps the original refresh token when the provider does not rotate', function (): void {
        $this->provider->rotateRefreshTokens = false;
        $result = ($this->refresh)();

        expect($result->rotated)->toBeFalse()
            ->and($result->refreshToken)->toBe($this->refreshToken)
            ->and($result->tokens->refreshToken)->toBeNull();
    });

    it('keeps the original claims when the provider returns no ID token', function (): void {
        $this->provider->idTokenOnRefresh = false;
        $result = ($this->refresh)();

        expect($result->idTokenRenewed)->toBeFalse()
            ->and($result->claims)->toBe($this->original);
    });

    it('asks for narrower scopes when given', function (): void {
        $result = ($this->refresh)(scopes: ['openid', 'email']);

        expect($this->provider->tokenRequests[0]['form'])->toMatchArray(['scope' => 'openid email'])
            ->and($result->tokens->scopes)->toBe(['openid', 'email']);
    });

    it('accepts a new ID token without a nonce, or with the original one', function (array $claims): void {
        $this->provider->refreshClaims = $claims;

        expect(($this->refresh)()->claims->subject)->toBe('user-1');
    })->with([
        'no nonce' => [['nonce' => null]],
        'the original nonce' => [['nonce' => 'nonce-1']],
        'no auth_time' => [['auth_time' => null]],
    ]);

    it('keeps the groups read from userinfo', function (): void {
        Refusals::useConnection('main', ConnectionFixtures::minimal(['groups' => ['source' => 'userinfo']]));
        $original = ($this->login)()->withGroups(['staff']);

        expect(($this->refresh)($original)->claims->groups)->toBe(['staff']);
    });

    it('works with the refresh token of a whole login', function (): void {
        $flow = resolve(AuthorizationFlow::class);
        $request = $flow->start();
        $login = $flow->callback(Request::create('https://app.example.test/oidc/callback', 'GET', $this->provider->approve($request->url)));

        $result = resolve(TokenRefresher::class)->refresh($login->claims, (string) $login->tokens->refreshToken);

        expect($result->claims->subject)->toBe($login->claims->subject)
            ->and($result->claims->authTime)->toEqual($login->claims->authTime);
    });

    it('keeps tokens out of dumps', function (): void {
        $dump = print_r(($this->refresh)(), true);

        expect($dump)->not->toContain($this->refreshToken)->toContain('[redacted]');
    });
});

describe('a refresh the provider refuses', function (): void {
    it('says the person must sign in again when the refresh token is no longer valid', function (): void {
        $exception = Refusals::assert(fn () => ($this->refresh)(refreshToken: 'revoked-token'), ErrorCode::TokenRequestRejected, TokenRequestRejected::class, 'refused the request with HTTP 400 and the error invalid_grant');

        expect($exception)->toBeInstanceOf(TokenRequestRejected::class);
        assert($exception instanceof TokenRequestRejected);
        expect($exception->refreshTokenInvalid())->toBeTrue()
            ->and($exception->grant())->toBe('refresh_token')
            ->and($exception->fix())->toContain('sign the person in again');
    });

    it('does not take another error for an invalid refresh token', function (): void {
        $this->provider->clients = ['client-1' => ['secret' => 'another-secret']];
        $exception = Refusals::assert(fn () => ($this->refresh)(), ErrorCode::TokenRequestRejected, TokenRequestRejected::class, 'invalid_client');
        assert($exception instanceof TokenRequestRejected);

        expect($exception->refreshTokenInvalid())->toBeFalse();
    });

    it('reports an unavailable provider as retryable', function (): void {
        $this->provider->tokenResponse = fn (): mixed => Factory::response('', 503);

        Refusals::assert(fn () => ($this->refresh)(), ErrorCode::ProviderUnavailable, ProviderUnavailable::class);
    });

    it('refuses a malformed refresh token or scope before calling the provider', function (string $token, ?array $scopes): void {
        Refusals::assert(fn () => ($this->refresh)(refreshToken: $token, scopes: $scopes), ErrorCode::ArgumentInvalid, InvalidArgument::class);

        expect($this->provider->tokenRequests)->toBe([]);
    })->with([
        'empty' => ['', null],
        'a newline' => ["token\n", null],
        'too long' => [str_repeat('a', 16385), null],
        'a scope with a space' => ['token', ['open id']],
        'an empty scope' => ['token', ['']],
    ]);
});

describe('the ID token a refresh returns', function (): void {
    it('must name the same subject', function (): void {
        $this->provider->refreshClaims = ['sub' => 'user-2'];

        Refusals::assert(fn () => ($this->refresh)(), ErrorCode::RefreshedIdTokenMismatch, TokenRejected::class, 'names another subject than the login it renews', 'sub');
    });

    it('must keep the original auth_time when it has one', function (): void {
        $this->provider->refreshClaims = ['auth_time' => $this->now];

        Refusals::assert(fn () => ($this->refresh)(), ErrorCode::RefreshedIdTokenMismatch, TokenRejected::class, 'says the person signed in at', 'auth_time');
    });

    it('must keep the original nonce when it has one', function (): void {
        $this->provider->refreshClaims = ['nonce' => 'nonce-2'];

        Refusals::assert(fn () => ($this->refresh)(), ErrorCode::RefreshedIdTokenMismatch, TokenRejected::class, 'has another nonce', 'nonce');
    });

    it('must not carry a nonce the original did not have', function (): void {
        $original = ($this->login)(['nonce' => null]);
        $this->provider->refreshClaims = ['nonce' => 'nonce-1'];

        Refusals::assert(fn () => ($this->refresh)($original), ErrorCode::RefreshedIdTokenMismatch, TokenRejected::class, 'has another nonce', 'nonce');
    });

    it('passes every rule of an ID token', function (array $claims, ErrorCode $code, string $claim): void {
        $this->provider->refreshClaims = $claims;

        Refusals::assert(fn () => ($this->refresh)(), $code, TokenRejected::class, '', $claim);
    })->with([
        'another issuer' => [['iss' => 'https://evil.example.test'], ErrorCode::TokenIssuerMismatch, 'iss'],
        'another audience' => [['aud' => 'client-2'], ErrorCode::TokenAudienceInvalid, 'aud'],
        'expired' => [['exp' => 1000], ErrorCode::TokenExpired, 'exp'],
        'a wrong at_hash' => [['at_hash' => 'AAAAAAAAAAAAAAAAAAAAAA'], ErrorCode::IdTokenAtHashMismatch, 'at_hash'],
    ]);

    it('must renew a login of the same connection', function (): void {
        // One provider behind two connections: a login of main may not be
        // renewed as one of the other.
        Refusals::useConnection('second', ConnectionFixtures::minimal(['redirect_uri' => 'https://app.example.test/oidc/second/callback']));
        $token = $this->provider->idToken(['auth_time' => $this->now - 100]);

        Refusals::assert(
            fn () => resolve(IdTokenVerifier::class)->verify('second', $token, IdTokenExpectations::forRefresh($this->original)),
            ErrorCode::RefreshedIdTokenMismatch,
            TokenRejected::class,
            'renews a login of connection "main"',
            'iss',
        );
    });

    it('must name the issuer of the login it renews, also where a tenant template allows another', function (): void {
        $tenantOne = '11111111-1111-1111-1111-111111111111';
        $tenantTwo = '22222222-2222-2222-2222-222222222222';
        $entra = FakeProvider::entra()->install();
        Refusals::useConnection('entra', [...ConnectionFixtures::entraMultiTenant(), 'client_id' => 'client-1', 'client_secret' => 'secret-1', 'algorithms' => ['RS256']]);
        $original = ($this->login)(['tid' => $tenantOne], 'entra', $entra);

        // Both tenants are allowed, so the token passes every other rule.
        $entra->refreshClaims = ['tid' => $tenantTwo, 'iss' => 'https://login.microsoftonline.com/'.$tenantTwo.'/v2.0'];

        Refusals::assert(
            fn () => resolve(TokenRefresher::class)->refresh($original, $entra->issueRefreshToken($original->claims)),
            ErrorCode::RefreshedIdTokenMismatch,
            TokenRejected::class,
            'names the issuer "https://login.microsoftonline.com/'.$tenantTwo.'/v2.0", but the login it renews was issued by "https://login.microsoftonline.com/'.$tenantOne.'/v2.0"',
            'iss',
        );
    });

    it('must name the same tenant', function (): void {
        Refusals::useConnection('workspace', [...ConnectionFixtures::google(), 'tenant' => ['claim' => 'hd', 'allowed' => ['example.com', 'example.org']]]);
        $google = new FakeProvider('https://accounts.google.com')->install();
        $google->clients = ['google-client' => ['secret' => 'google-secret']];
        $google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];
        $original = ($this->login)(['aud' => 'google-client', 'hd' => 'example.com'], 'workspace', $google);
        $google->refreshClaims = ['hd' => 'example.org'];

        Refusals::assert(fn () => resolve(TokenRefresher::class)->refresh($original, $google->issueRefreshToken($original->claims, 'google-client')), ErrorCode::RefreshedIdTokenMismatch, TokenRejected::class, 'names another tenant', 'hd');

        $google->refreshClaims = ['hd' => 'other.example'];

        Refusals::assert(fn () => resolve(TokenRefresher::class)->refresh($original, $google->issueRefreshToken($original->claims, 'google-client')), ErrorCode::TenantNotAllowed, TenantRejected::class, '', 'hd');
    });
});

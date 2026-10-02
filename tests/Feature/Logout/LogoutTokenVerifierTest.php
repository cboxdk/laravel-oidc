<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\LogoutTokenRejected;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Logout\LogoutToken;
use Cbox\Oidc\Logout\LogoutTokenReplayGuard;
use Cbox\Oidc\Logout\LogoutTokenVerifier;
use Cbox\Oidc\Support\Base64Url;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tests\Support\Refusals;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Signature\Algorithm\HS256;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->now = now()->getTimestamp();
    $this->provider = new FakeProvider()->install();
    $this->verify = fn (string $token, string $connection = 'main'): LogoutToken => resolve(LogoutTokenVerifier::class)->verify($connection, $token);
    $this->token = fn (array $claims = [], SigningAlgorithm $algorithm = SigningAlgorithm::RS256, array $header = [], ?JWK $key = null): string => $this->provider->logoutToken($claims, $algorithm, $header, $key);
    $this->refused = fn (array $claims, ErrorCode $code, ?string $claim, string $message = '', string $class = LogoutTokenRejected::class, array $header = []): mixed => Refusals::assert(fn (): LogoutToken => ($this->verify)(($this->token)($claims, header: $header)), $code, $class, $message, $claim);
});

describe('a valid logout token', function (): void {
    it('verifies with each kind of key', function (SigningAlgorithm $algorithm): void {
        $token = ($this->verify)(($this->token)(['jti' => 'jti-1'], $algorithm));

        expect($token->connection)->toBe('main')
            ->and($token->issuer)->toBe(FakeProvider::ISSUER)
            ->and($token->subject)->toBe('user-1')
            ->and($token->sessionId)->toBe('session-1')
            ->and($token->jti)->toBe('jti-1')
            ->and($token->issuedAt->getTimestamp())->toBe($this->now)
            ->and($token->expiresAt->getTimestamp())->toBe($this->now + 120)
            ->and($token->endsOneSession())->toBeTrue()
            ->and($token->claim('events'))->toBe([LogoutTokenVerifier::EVENT => []])
            ->and($token->claim('missing', 'x'))->toBe('x');
    })->with([SigningAlgorithm::RS256, SigningAlgorithm::ES256, SigningAlgorithm::EdDSA]);

    it('may name only a subject, or only a session', function (array $claims, ?string $subject, ?string $sid): void {
        $token = ($this->verify)(($this->token)($claims));

        expect($token->subject)->toBe($subject)
            ->and($token->sessionId)->toBe($sid)
            ->and($token->endsOneSession())->toBe($sid !== null);
    })->with([
        'only sub' => [['sid' => null], 'user-1', null],
        'only sid' => [['sub' => null], null, 'session-1'],
    ]);

    it('accepts the types providers use for logout tokens', function (?string $type): void {
        expect(($this->verify)(($this->token)(header: ['typ' => $type]))->subject)->toBe('user-1');
    })->with(['logout+jwt', 'Logout+JWT', 'application/logout+jwt', 'JWT', null]);

    it('accepts extra members of the event and other events', function (): void {
        $token = ($this->verify)(($this->token)(['events' => [LogoutTokenVerifier::EVENT => ['reason' => 'admin'], 'https://example.test/other' => new stdClass]]));

        expect($token->subject)->toBe('user-1');
    });

    it('tells which sessions it ends', function (): void {
        $verifier = resolve(IdTokenVerifier::class);
        $signedIn = fn (array $claims): mixed => $verifier->verify('main', $this->provider->idToken($claims), new IdTokenExpectations('nonce-1'));

        $bySession = ($this->verify)(($this->token)(['sub' => null]));
        $bySubject = ($this->verify)(($this->token)(['sid' => null]));
        $byBoth = ($this->verify)(($this->token)());

        expect($bySession->matches($signedIn(['sid' => 'session-1', 'sub' => 'user-9'])))->toBeTrue()
            ->and($bySession->matches($signedIn(['sid' => 'session-2'])))->toBeFalse()
            ->and($bySession->matches($signedIn([])))->toBeFalse()
            ->and($bySubject->matches($signedIn(['sid' => 'session-7'])))->toBeTrue()
            ->and($bySubject->matches($signedIn(['sub' => 'user-2'])))->toBeFalse()
            ->and($byBoth->matches($signedIn(['sid' => 'session-1'])))->toBeTrue()
            ->and($byBoth->matches($signedIn(['sid' => 'session-1', 'sub' => 'user-2'])))->toBeFalse();
    });
});

describe('the rules a logout token shares with an ID token', function (): void {
    it('refuses another kind of token', function (string $type): void {
        ($this->refused)([], ErrorCode::TokenTypeInvalid, 'typ', 'has the typ', TokenRejected::class, ['typ' => $type]);
    })->with(['at+jwt', 'id_token+jwt', 'secevent+jwt', 'JWS']);

    it('refuses alg none and shared-secret algorithms', function (): void {
        $none = Base64Url::encode('{"alg":"none","typ":"logout+jwt"}').'.'.Base64Url::encode(json_encode(['iss' => FakeProvider::ISSUER], JSON_THROW_ON_ERROR)).'.';
        Refusals::assert(fn () => ($this->verify)($none), ErrorCode::TokenMalformed, TokenRejected::class);

        $hs = new CompactSerializer()->serialize(new JWSBuilder(new AlgorithmManager([new HS256]))
            ->create()->withPayload('{"iss":"https://idp.example.test"}')
            ->addSignature(new JWK(['kty' => 'oct', 'k' => Base64Url::encode(str_repeat('k', 32))]), ['alg' => 'HS256', 'kid' => 'rsa-1'])
            ->build(), 0);
        Refusals::assert(fn () => ($this->verify)($hs), ErrorCode::TokenAlgorithmNotAllowed, TokenRejected::class, 'which is never accepted', 'alg');
    });

    it('refuses a forged signature', function (): void {
        [$header, $payload, $signature] = explode('.', ($this->token)());
        $forged = $header.'.'.Base64Url::encode(str_replace('user-1', 'user-2', (string) Base64Url::decode($payload))).'.'.$signature;

        Refusals::assert(fn () => ($this->verify)($forged), ErrorCode::TokenSignatureInvalid, TokenRejected::class);
    });

    it('refuses a token that is not a compact JWS', function (string $token): void {
        Refusals::assert(fn () => ($this->verify)($token), ErrorCode::TokenMalformed, TokenRejected::class);
    })->with(['', 'a.b', 'a.b.c.d.e']);

    it('checks iss, aud, azp and the lifetime as for an ID token', function (array $claims, ErrorCode $code, string $claim): void {
        ($this->refused)($claims, $code, $claim, '', TokenRejected::class);
    })->with([
        'another issuer' => [['iss' => 'https://evil.example.test'], ErrorCode::TokenIssuerMismatch, 'iss'],
        'no issuer' => [['iss' => null], ErrorCode::TokenIssuerMismatch, 'iss'],
        'another audience' => [['aud' => 'client-2'], ErrorCode::TokenAudienceInvalid, 'aud'],
        'several audiences without azp' => [['aud' => ['client-1', 'client-2']], ErrorCode::TokenAudienceInvalid, 'azp'],
        'another azp' => [['azp' => 'client-2'], ErrorCode::TokenAudienceInvalid, 'azp'],
        'no exp' => [['exp' => null], ErrorCode::TokenClaimInvalid, 'exp'],
        'expired' => [['exp' => 1000, 'iat' => 900], ErrorCode::TokenExpired, 'exp'],
        'no iat' => [['iat' => null], ErrorCode::TokenClaimInvalid, 'iat'],
        'issued in the future' => [['iat' => 4102444800, 'exp' => 4102444900], ErrorCode::TokenNotYetValid, 'iat'],
        'not valid yet' => [['nbf' => 4102444800], ErrorCode::TokenNotYetValid, 'nbf'],
        'a malformed sub' => [['sub' => "user\n1"], ErrorCode::TokenClaimInvalid, 'sub'],
    ]);

    it('refuses a token issued longer ago than max_token_age_seconds', function (): void {
        ($this->refused)(['iat' => $this->now - 661, 'exp' => $this->now + 60], ErrorCode::TokenStale, 'iat', '', TokenRejected::class);
    });
});

describe('the rules only a logout token has', function (): void {
    it('refuses a token without the back-channel logout event', function (mixed $events, string $message): void {
        ($this->refused)(['events' => $events], ErrorCode::LogoutTokenInvalid, 'events', $message);
    })->with([
        'no events' => [null, 'has no events claim'],
        'events as a list' => [[LogoutTokenVerifier::EVENT], 'has no events claim, or one that is not a JSON object'],
        'events as an empty list' => [[], 'has no events claim, or one that is not a JSON object'],
        'events as a string' => [LogoutTokenVerifier::EVENT, 'has no events claim, or one that is not a JSON object'],
        'another event only' => [['https://example.test/other' => new stdClass], 'has no http://schemas.openid.net/event/backchannel-logout event'],
        'an empty events object' => [new stdClass, 'has no http://schemas.openid.net/event/backchannel-logout event'],
        'the event as true' => [[LogoutTokenVerifier::EVENT => true], 'whose value is not a JSON object'],
        'the event as a list' => [[LogoutTokenVerifier::EVENT => []], 'whose value is not a JSON object'],
        'the event as a string' => [[LogoutTokenVerifier::EVENT => 'logout'], 'whose value is not a JSON object'],
    ]);

    it('refuses a token with a nonce, so an ID token never passes as one', function (mixed $nonce): void {
        ($this->refused)(['nonce' => $nonce], ErrorCode::LogoutTokenInvalid, 'nonce', 'has a nonce');
    })->with(['nonce-1', '', 0]);

    it('refuses an ID token offered as a logout token', function (): void {
        Refusals::assert(fn () => ($this->verify)($this->provider->idToken()), ErrorCode::LogoutTokenInvalid, LogoutTokenRejected::class, 'has no events claim', 'events');
    });

    it('refuses a token that names no session', function (): void {
        ($this->refused)(['sub' => null, 'sid' => null], ErrorCode::LogoutTokenInvalid, 'sub', 'names neither a sub nor a sid');
    });

    it('refuses a malformed sid', function (mixed $sid): void {
        ($this->refused)(['sid' => $sid], ErrorCode::LogoutTokenInvalid, 'sid', 'has a sid that is not');
    })->with(['', 5, [['session-1']], str_repeat('s', 256)]);

    it('refuses a token without a usable jti', function (mixed $jti): void {
        ($this->refused)(['jti' => $jti], ErrorCode::LogoutTokenInvalid, 'jti', 'has no jti');
    })->with([null, '', 42, "jti\n"]);
});

describe('replays', function (): void {
    it('accepts a token once', function (): void {
        $token = ($this->token)();
        ($this->verify)($token);

        Refusals::assert(fn () => ($this->verify)($token), ErrorCode::LogoutTokenReplayed, LogoutTokenRejected::class, 'was accepted already', 'jti');
    });

    it('refuses another token with a jti it accepted', function (): void {
        ($this->verify)(($this->token)(['jti' => 'jti-1']));

        Refusals::assert(fn () => ($this->verify)(($this->token)(['jti' => 'jti-1', 'sid' => 'session-2'])), ErrorCode::LogoutTokenReplayed, LogoutTokenRejected::class, '', 'jti');
    });

    it('does not use up the jti of a token refused for another reason', function (): void {
        ($this->refused)(['jti' => 'jti-1', 'nonce' => 'n'], ErrorCode::LogoutTokenInvalid, 'nonce');

        expect(($this->verify)(($this->token)(['jti' => 'jti-1']))->jti)->toBe('jti-1');
    });

    it('keeps the jti of each connection and issuer apart', function (): void {
        $google = new FakeProvider('https://accounts.google.com')->install();
        $google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];

        ($this->verify)(($this->token)(['jti' => 'jti-1']));

        expect(($this->verify)($google->logoutToken(['jti' => 'jti-1', 'aud' => 'google-client']), 'workspace')->jti)->toBe('jti-1');
    });

    it('remembers a jti until the token can no longer be valid', function (): void {
        $guard = resolve(LogoutTokenReplayGuard::class);
        $exp = $this->now + 120;

        expect($guard->claim('main', FakeProvider::ISSUER, 'jti-9', $exp, 60))->toBeTrue();

        $this->travelTo(now()->addSeconds(120 + 60 + 59));
        expect($guard->claim('main', FakeProvider::ISSUER, 'jti-9', $exp, 60))->toBeFalse();

        $this->travelTo(now()->addSeconds(2));
        expect($guard->claim('main', FakeProvider::ISSUER, 'jti-9', $exp, 60))->toBeTrue();
    });
});

describe('Microsoft Entra multi-tenant ({tenantid})', function (): void {
    beforeEach(function (): void {
        $this->entra = FakeProvider::entra()->install();
        Refusals::useConnection('entra', [
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'discovery_url' => 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            'client_id' => 'client-1',
            'client_secret' => 'secret-1',
            'redirect_uri' => 'https://app.example.test/oidc/entra/callback',
            'algorithms' => ['RS256'],
            'tenant' => ['claim' => 'tid', 'allowed' => ['11111111-1111-1111-1111-111111111111']],
        ]);
    });

    it('reads the issuer of the token\'s tenant', function (): void {
        $token = ($this->verify)($this->entra->logoutToken(['tid' => '11111111-1111-1111-1111-111111111111']), 'entra');

        expect($token->issuer)->toBe('https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0');
    });

    it('needs the tid to know the issuer', function (): void {
        Refusals::assert(fn () => ($this->verify)($this->entra->logoutToken([]), 'entra'), ErrorCode::TenantClaimMissing, TenantRejected::class, 'The logout token of connection "entra" has no tid claim', 'tid');
    });
});

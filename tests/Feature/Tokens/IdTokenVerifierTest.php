<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\SigningKeyNotFound;
use Cbox\Oidc\Exceptions\SigningKeyUnsuitable;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Support\Base64Url;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\RSAKey;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->now = now()->getTimestamp();
    $this->provider = new FakeProvider()->install();
    $this->verify = fn (string $token, ?IdTokenExpectations $expected = null, string $connection = 'main'): VerifiedClaims => resolve(IdTokenVerifier::class)->verify($connection, $token, $expected ?? new IdTokenExpectations('nonce-1'));
    $this->token = fn (array $claims = [], SigningAlgorithm $algorithm = SigningAlgorithm::RS256, array $header = [], ?JWK $key = null): string => $this->provider->idToken($claims, $algorithm, $header, $key);
});

/**
 * Runs $call and checks that it throws $class with $code (and $claim).
 *
 * @param  class-string<OidcException>  $class
 */
function refusedWith(Closure $call, ErrorCode $code, ?string $claim = null, string $message = '', string $class = TokenRejected::class): void
{
    try {
        $call();
    } catch (OidcException $exception) {
        expect($exception)->toBeInstanceOf($class)
            ->and($exception->errorCode())->toBe($code)
            ->and($exception->getMessage())->toContain($message)->not->toContain('nonce-1');

        if ($exception instanceof TokenRejected) {
            expect($exception->claim())->toBe($claim);
        }

        return;
    }

    test()->fail(sprintf('Expected %s, but nothing was thrown.', $code->value));
}

/**
 * A token of the given header and claims, with $signature as its third part.
 *
 * @param  array<string, mixed>  $header
 * @param  array<string, mixed>  $claims
 */
function rawToken(array $header, array $claims, string $signature = 'c2lnbmF0dXJl'): string
{
    return Base64Url::encode(json_encode($header, JSON_THROW_ON_ERROR)).'.'.Base64Url::encode(json_encode($claims, JSON_THROW_ON_ERROR)).'.'.$signature;
}

function useConnection(string $name, array $values): void
{
    config(['oidc.connections.'.$name => $values]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(IdTokenVerifier::class);
}

describe('a valid ID token', function (): void {
    it('verifies with each kind of key', function (SigningAlgorithm $algorithm): void {
        $claims = ($this->verify)(($this->token)(algorithm: $algorithm));

        expect($claims->connection)->toBe('main')
            ->and($claims->issuer)->toBe(FakeProvider::ISSUER)
            ->and($claims->subject)->toBe('user-1')
            ->and($claims->audience)->toBe(['client-1'])
            ->and($claims->issuedAt->getTimestamp())->toBe($this->now)
            ->and($claims->expiresAt->getTimestamp())->toBe($this->now + 300);
    })->with([SigningAlgorithm::RS256, SigningAlgorithm::ES256, SigningAlgorithm::EdDSA]);

    it('gives the claims typed and raw', function (): void {
        $claims = ($this->verify)(($this->token)([
            'auth_time' => $this->now - 30,
            'amr' => ['pwd', 'mfa', 'pwd'],
            'acr' => 'urn:example:loa2',
            'sid' => 'session-9',
            'email' => 'ada@example.com',
            'email_verified' => true,
            'name' => 'Ada Lovelace',
            'groups' => ['admins', 'staff', 'admins'],
            'locale' => 'da',
        ]));

        expect($claims->authTime?->getTimestamp())->toBe($this->now - 30)
            ->and($claims->authenticationMethods)->toBe(['pwd', 'mfa'])
            ->and($claims->authenticationContext)->toBe('urn:example:loa2')
            ->and($claims->sessionId)->toBe('session-9')
            ->and($claims->groups)->toBe(['admins', 'staff'])
            ->and($claims->groupsOverage)->toBeFalse()
            ->and($claims->tenant)->toBeNull()
            ->and($claims->authorizedParty)->toBeNull()
            ->and($claims->email())->toBe('ada@example.com')
            ->and($claims->emailVerified())->toBeTrue()
            ->and($claims->name())->toBe('Ada Lovelace')
            ->and($claims->string('locale'))->toBe('da')
            ->and($claims->string('auth_time'))->toBeNull()
            ->and($claims->claim('locale'))->toBe('da')
            ->and($claims->claim('missing', 'fallback'))->toBe('fallback')
            ->and($claims->has('locale'))->toBeTrue()
            ->and($claims->has('missing'))->toBeFalse()
            ->and($claims->all())->toHaveKeys(['iss', 'sub', 'aud', 'nonce', 'locale']);
    });

    it('leaves optional claims out when the token has none', function (): void {
        $claims = ($this->verify)(($this->token)());

        expect($claims->authTime)->toBeNull()
            ->and($claims->authenticationMethods)->toBeNull()
            ->and($claims->authenticationContext)->toBeNull()
            ->and($claims->sessionId)->toBeNull()
            ->and($claims->groups)->toBe([])
            ->and($claims->email())->toBeNull()
            ->and($claims->emailVerified())->toBeFalse();
    });

    it('trusts email_verified only as the JSON value true', function (mixed $value): void {
        expect(($this->verify)(($this->token)(['email_verified' => $value]))->emailVerified())->toBeFalse();
    })->with(['the string true' => 'true', 'one' => 1, 'false' => false]);

    it('accepts several audiences when azp names the client', function (): void {
        $claims = ($this->verify)(($this->token)(['aud' => ['client-1', 'api'], 'azp' => 'client-1']));

        expect($claims->audience)->toBe(['client-1', 'api'])
            ->and($claims->authorizedParty)->toBe('client-1');
    });

    it('accepts a list audience with only the client and no azp', function (): void {
        expect(($this->verify)(($this->token)(['aud' => ['client-1']]))->audience)->toBe(['client-1']);
    });

    it('accepts any typ but that of another kind of token', function (?string $type): void {
        expect(($this->verify)(($this->token)(header: ['typ' => $type]))->subject)->toBe('user-1');
    })->with(['none' => null, 'JWT' => 'JWT', 'jwt' => 'jwt', 'application/jwt' => 'application/jwt']);

    it('checks at_hash against the access token, with the hash of each algorithm', function (SigningAlgorithm $algorithm): void {
        $token = ($this->token)(['at_hash' => $algorithm->accessTokenHash('access-1')], $algorithm);

        expect(($this->verify)($token, new IdTokenExpectations('nonce-1', accessToken: 'access-1'))->subject)->toBe('user-1');
        refusedWith(fn () => ($this->verify)($token, new IdTokenExpectations('nonce-1', accessToken: 'access-2')), ErrorCode::IdTokenAtHashMismatch, 'at_hash');
    })->with([SigningAlgorithm::RS256, SigningAlgorithm::ES256, SigningAlgorithm::EdDSA]);

    it('skips at_hash when no access token is given', function (): void {
        expect(($this->verify)(($this->token)(['at_hash' => 'not-the-hash']))->subject)->toBe('user-1');
    });

    it('does not ask for a nonce when none was sent', function (): void {
        expect(($this->verify)(($this->token)(['nonce' => null]), new IdTokenExpectations(null))->subject)->toBe('user-1');
    });

    it('reads fractional times as whole seconds', function (): void {
        expect(($this->verify)(($this->token)(['iat' => $this->now + 0.75, 'exp' => $this->now + 300.5]))->expiresAt->getTimestamp())->toBe($this->now + 300);
    });
});

describe('the form of the token', function (): void {
    it('refuses what is not a compact JWS', function (Closure $token, string $message, ?string $claim = null): void {
        refusedWith(fn () => ($this->verify)($token->call($this)), ErrorCode::TokenMalformed, $claim, $message);
    })->with([
        'too long' => [fn (): string => ($this->token)(['pad' => str_repeat('a', 16384)]), 'more than the 16384 the package reads'],
        'two parts' => [fn (): string => 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0', 'is not a compact JWS'],
        'an empty signature' => [fn (): string => rawToken(['alg' => 'none'], ['sub' => 'x'], ''), 'is not a compact JWS'],
        'an encrypted token' => [fn (): string => 'eyJhbGciOiJSU0EtT0FFUCJ9.a.b.c.d', 'is encrypted (a JWE)'],
        'JSON serialization' => [fn (): string => '{"payload":"e30","signatures":[]}', 'is not a compact JWS'],
        'padding' => [fn (): string => ($this->token)().'=', 'is not a compact JWS'],
        'a header that is not JSON' => [fn (): string => Base64Url::encode('not json').'.e30.c2ln', 'a header that is not a JSON object'],
        'a header that is a list' => [fn (): string => Base64Url::encode('["RS256"]').'.e30.c2ln', 'a header that is not a JSON object'],
        'a header with a key twice' => [fn (): string => Base64Url::encode('{"alg":"RS256","alg":"none"}').'.e30.c2ln', 'a header that is not a JSON object'],
        'a header in non-canonical base64url' => [fn (): string => 'eyJhbGciOiJSUzI1NiIsImtpZCI6InJzYS0xIn1.e30.c2ln', 'a header that is not a JSON object'],
        'crit' => [fn (): string => ($this->token)(header: ['crit' => ['exp'], 'exp' => 1]), 'has the header member crit', 'crit'],
        'b64' => [fn (): string => rawToken(['alg' => 'RS256', 'kid' => 'rsa-1', 'b64' => false], ['sub' => 'x']), 'has the header member b64', 'b64'],
        'a typ that is not a string' => [fn (): string => ($this->token)(header: ['typ' => 1]), 'has a typ that is not a string', 'typ'],
        'an empty kid' => [fn (): string => ($this->token)(header: ['kid' => '']), 'has a kid that is not a non-empty string', 'kid'],
        'a payload that is not JSON' => [fn (): string => signedPayload($this->provider, 'not json'), 'a payload that is not a JSON object'],
        'a payload with a key twice' => [fn (): string => signedPayload($this->provider, '{"sub":"a","sub":"b"}'), 'a payload that is not a JSON object'],
        'a payload that is a list' => [fn (): string => signedPayload($this->provider, '["sub"]'), 'a payload that is not a JSON object'],
    ]);

    it('refuses the token of another kind', function (string $type): void {
        refusedWith(fn () => ($this->verify)(($this->token)(header: ['typ' => $type])), ErrorCode::TokenTypeInvalid, 'typ', 'the type of another kind of token');
    })->with(['logout+jwt', 'application/logout+jwt', 'at+jwt', 'AT+JWT']);
});

describe('the algorithm', function (): void {
    it('never accepts an unsigned token', function (string $alg): void {
        refusedWith(fn () => ($this->verify)(rawToken(['alg' => $alg, 'kid' => 'rsa-1'], ['iss' => FakeProvider::ISSUER, 'sub' => 'x', 'aud' => 'client-1', 'nonce' => 'nonce-1'])), ErrorCode::TokenAlgorithmNotAllowed, 'alg', 'which is never accepted');
    })->with(['none', 'None', 'NONE']);

    it('refuses an HMAC token signed with the provider\'s public key as the secret (alg confusion)', function (string $alg): void {
        $public = $this->provider->key('rsa-1')->toPublic();
        $pem = RSAKey::createFromJWK($public)->toPEM();
        $input = Base64Url::encode(json_encode(['alg' => $alg, 'kid' => 'rsa-1', 'typ' => 'JWT'], JSON_THROW_ON_ERROR)).'.'.Base64Url::encode(json_encode(['iss' => FakeProvider::ISSUER, 'sub' => 'attacker', 'aud' => 'client-1', 'iat' => $this->now, 'exp' => $this->now + 300, 'nonce' => 'nonce-1'], JSON_THROW_ON_ERROR));
        $token = $input.'.'.Base64Url::encode(hash_hmac('sha'.substr($alg, 2), $input, $pem, true));

        refusedWith(fn () => ($this->verify)($token), ErrorCode::TokenAlgorithmNotAllowed, 'alg', sprintf('uses alg %s, which is never accepted', $alg));
    })->with(['HS256', 'HS384', 'HS512']);

    it('refuses a token without alg', function (): void {
        refusedWith(fn () => ($this->verify)(rawToken(['kid' => 'rsa-1'], ['sub' => 'x'])), ErrorCode::TokenAlgorithmNotAllowed, 'alg', 'names no alg');
    });

    it('refuses an algorithm the connection does not accept', function (): void {
        useConnection('main', [...config('oidc.connections.main'), 'algorithms' => ['ES256']]);

        refusedWith(fn () => ($this->verify)(($this->token)()), ErrorCode::TokenAlgorithmNotAllowed, 'alg', 'uses alg RS256, which is not one of the algorithms accepted for it (ES256)');
    });

    it('refuses an algorithm the provider does not list, though the connection accepts it', function (): void {
        refusedWith(fn () => ($this->verify)(($this->token)(algorithm: SigningAlgorithm::PS256)), ErrorCode::TokenAlgorithmNotAllowed, 'alg', 'uses alg PS256');
    });

    it('refuses an algorithm web-token does not know', function (): void {
        refusedWith(fn () => ($this->verify)(rawToken(['alg' => 'ES256K', 'kid' => 'ec-1'], ['sub' => 'x'])), ErrorCode::TokenAlgorithmNotAllowed, 'alg', 'uses alg ES256K');
    });
});

describe('the key and the signature', function (): void {
    it('refuses a token whose kid the provider does not publish, after one refetch', function (): void {
        $token = ($this->token)(key: FakeProvider::rsaKey('rsa-retired'));

        expect(fn () => ($this->verify)($token))->toThrow(SigningKeyNotFound::class, 'has no key with kid "rsa-retired" (also after refetching the key set)')
            ->and($this->provider->jwksRequests)->toBe(2);
    });

    it('refuses a token whose kid names a key of another type', function (): void {
        expect(fn () => ($this->verify)(($this->token)(header: ['kid' => 'ec-1'])))->toThrow(SigningKeyUnsuitable::class, 'it is a EC key, and RS256 takes RSA');
    });

    it('refuses a token signed with a key that expired or was revoked', function (array $values, string $problem): void {
        $this->provider->keys = [FakeProvider::rsaKey('rsa-1', values: $values)];

        expect(fn () => ($this->verify)(($this->token)()))->toThrow(SigningKeyUnsuitable::class, $problem);
    })->with([
        'expired' => [fn (): array => ['exp' => $this->now - 1], 'it expired at'],
        'not valid yet' => [fn (): array => ['nbf' => $this->now + 60], 'it is not valid before'],
        'revoked' => [['revoked' => ['revoked_at' => 1]], 'it is marked revoked'],
    ]);

    it('refuses a signature made with another key under the provider\'s kid', function (): void {
        $forged = ($this->token)(key: FakeProvider::rsaKey('rsa-1-attacker', values: ['kid' => 'rsa-1']));

        refusedWith(fn () => ($this->verify)($forged), ErrorCode::TokenSignatureInvalid, null, 'does not verify with the provider\'s key "rsa-1"');
    });

    it('refuses a token whose payload was changed after signing', function (): void {
        [$header, , $signature] = explode('.', ($this->token)());
        $changed = $header.'.'.Base64Url::encode(json_encode(['iss' => FakeProvider::ISSUER, 'sub' => 'admin', 'aud' => 'client-1', 'iat' => $this->now, 'exp' => $this->now + 300, 'nonce' => 'nonce-1'], JSON_THROW_ON_ERROR)).'.'.$signature;

        refusedWith(fn () => ($this->verify)($changed), ErrorCode::TokenSignatureInvalid);
    });

    it('never takes the key from the token header', function (string $member): void {
        $attacker = FakeProvider::rsaKey('attacker');
        $values = ['jwk' => $attacker->toPublic()->all(), 'jku' => 'https://attacker.example.test/jwks', 'x5u' => 'https://attacker.example.test/cert', 'x5c' => ['MIIB']];
        $token = ($this->token)(header: ['kid' => null, $member => $values[$member]], key: $attacker);

        refusedWith(fn () => ($this->verify)($token), ErrorCode::TokenSignatureInvalid);
    })->with(['jwk', 'jku', 'x5u', 'x5c']);
});

describe('the issuer', function (): void {
    it('refuses a token of another issuer', function (mixed $iss, string $message): void {
        refusedWith(fn () => ($this->verify)(($this->token)(['iss' => $iss])), ErrorCode::TokenIssuerMismatch, 'iss', $message);
    })->with([
        'another host' => ['https://evil.example.test', 'names the issuer "https://evil.example.test", but the connection pins "https://idp.example.test"'],
        'a trailing slash' => [FakeProvider::ISSUER.'/', 'names the issuer "https://idp.example.test/"'],
        'another case' => ['https://IDP.example.test', 'names the issuer "https://IDP.example.test"'],
        'a number' => [1, 'has no iss'],
    ]);

    it('refuses a token without iss', function (): void {
        refusedWith(fn () => ($this->verify)(($this->token)(['iss' => null])), ErrorCode::TokenIssuerMismatch, 'iss', 'has no iss');
    });

    it('requires the issuer the callback named', function (): void {
        refusedWith(fn () => ($this->verify)(($this->token)(), new IdTokenExpectations('nonce-1', responseIssuer: 'https://other.example.test')), ErrorCode::TokenIssuerMismatch, 'iss', 'but the callback named "https://other.example.test" (RFC 9207)');
    });

    it('requires the issuer of the key that signed the token', function (): void {
        $this->provider->keys = [FakeProvider::rsaKey('rsa-1', values: ['issuer' => 'https://other.example.test'])];

        refusedWith(fn () => ($this->verify)(($this->token)()), ErrorCode::TokenIssuerMismatch, 'iss', 'but the key that signed it is for "https://other.example.test"');
    });
});

describe('the audience', function (): void {
    it('refuses a token that is not for the client', function (array $claims, string $message, string $claim = 'aud'): void {
        refusedWith(fn () => ($this->verify)(($this->token)($claims)), ErrorCode::TokenAudienceInvalid, $claim, $message);
    })->with([
        'another client' => [['aud' => 'client-2'], 'is not for the client "client-1"'],
        'a list without the client' => [['aud' => ['client-2', 'api']], 'is not for the client "client-1"'],
        'no aud' => [['aud' => null], 'has no aud'],
        'an empty list' => [['aud' => []], 'has no aud'],
        'a number' => [['aud' => 1], 'has no aud'],
        'a list with a number' => [['aud' => ['client-1', 2]], 'has no aud'],
        'an object' => [['aud' => ['client' => 'client-1']], 'has no aud'],
        'several audiences without azp' => [['aud' => ['client-1', 'api']], 'has several audiences and no azp', 'azp'],
        'azp of another client' => [['aud' => ['client-1', 'api'], 'azp' => 'api'], 'was issued to another client (azp is not "client-1")', 'azp'],
        'azp of another client with one audience' => [['azp' => 'client-2'], 'was issued to another client', 'azp'],
        'azp that is not a string' => [['azp' => ['client-1']], 'was issued to another client', 'azp'],
    ]);
});

describe('the lifetime', function (): void {
    it('allows the leeway on each side, and not a second more', function (array $claims, ?ErrorCode $code, ?string $claim = null): void {
        $call = fn () => ($this->verify)(($this->token)($claims));

        if (! $code instanceof ErrorCode) {
            expect($call()->subject)->toBe('user-1');
        } else {
            refusedWith($call, $code, $claim);
        }
    })->with([
        'exp at now minus leeway' => [fn (): array => ['exp' => $this->now - 60], null],
        'exp one second past it' => [fn (): array => ['exp' => $this->now - 61], ErrorCode::TokenExpired, 'exp'],
        'nbf at now plus leeway' => [fn (): array => ['nbf' => $this->now + 60], null],
        'nbf one second past it' => [fn (): array => ['nbf' => $this->now + 61], ErrorCode::TokenNotYetValid, 'nbf'],
        'iat at now plus leeway' => [fn (): array => ['iat' => $this->now + 60], null],
        'iat one second past it' => [fn (): array => ['iat' => $this->now + 61], ErrorCode::TokenNotYetValid, 'iat'],
        'iat at the age limit plus leeway' => [fn (): array => ['iat' => $this->now - 660], null],
        'iat one second older' => [fn (): array => ['iat' => $this->now - 661], ErrorCode::TokenStale, 'iat'],
    ]);

    it('names how far off the token is', function (): void {
        refusedWith(fn () => ($this->verify)(($this->token)(['exp' => $this->now - 100])), ErrorCode::TokenExpired, 'exp', 'expired 100 seconds ago (leeway 60 seconds)');
        refusedWith(fn () => ($this->verify)(($this->token)(['iat' => $this->now - 900])), ErrorCode::TokenStale, 'iat', 'was issued 900 seconds ago, longer than the 600 seconds');
    });

    it('uses the leeway the connection configures', function (): void {
        useConnection('main', [...config('oidc.connections.main'), 'leeway_seconds' => 0]);

        refusedWith(fn () => ($this->verify)(($this->token)(['exp' => $this->now - 1])), ErrorCode::TokenExpired, 'exp');
    });

    it('requires exp and iat as times', function (array $claims, string $claim, string $message): void {
        refusedWith(fn () => ($this->verify)(($this->token)($claims)), ErrorCode::TokenClaimInvalid, $claim, $message);
    })->with([
        'no exp' => [['exp' => null], 'exp', 'has no exp'],
        'exp as text' => [fn (): array => ['exp' => (string) ($this->now + 300)], 'exp', 'has a exp that is not a time'],
        'exp past the year 9999' => [['exp' => 253402300800], 'exp', 'has a exp that is not a time'],
        'no iat' => [['iat' => null], 'iat', 'has no iat'],
        'a negative iat' => [['iat' => -1], 'iat', 'has a iat that is not a time'],
        'nbf as a list' => [['nbf' => [1]], 'nbf', 'has a nbf that is not a time'],
    ]);
});

describe('the nonce', function (): void {
    it('requires the nonce of the login', function (array $claims, string $message): void {
        refusedWith(fn () => ($this->verify)(($this->token)($claims)), ErrorCode::IdTokenNonceMismatch, 'nonce', $message);
    })->with([
        'no nonce' => [['nonce' => null], 'has no nonce, although the login sent one'],
        'another nonce' => [['nonce' => 'nonce-2'], 'is not the nonce of this login'],
        'a nonce that is not a string' => [['nonce' => 1], 'has no nonce'],
    ]);
});

describe('the subject', function (): void {
    it('refuses a subject that is missing or malformed', function (mixed $sub): void {
        refusedWith(fn () => ($this->verify)(($this->token)(['sub' => $sub])), ErrorCode::TokenClaimInvalid, 'sub', 'has no sub, or one that is not 1 to 255 characters');
    })->with([
        'missing' => [null],
        'empty' => [''],
        'a number' => [42],
        '256 characters' => [str_repeat('a', 256)],
        'a newline' => ["user-1\n"],
        'a NUL byte' => ["user\0"],
    ]);

    it('accepts a subject of 255 characters', function (): void {
        expect(($this->verify)(($this->token)(['sub' => str_repeat('a', 255)]))->subject)->toHaveLength(255);
    });
});

describe('auth_time', function (): void {
    it('checks auth_time against max_age', function (?int $ago, ?int $maxAge, ?string $message): void {
        $call = fn () => ($this->verify)(($this->token)(['auth_time' => $ago === null ? null : $this->now - $ago]), new IdTokenExpectations('nonce-1', maxAge: $maxAge));

        if ($message === null) {
            expect($call()->subject)->toBe('user-1');
        } else {
            refusedWith($call, ErrorCode::IdTokenAuthTimeInvalid, 'auth_time', $message);
        }
    })->with([
        'within max_age' => [300, 300, null],
        'at max_age plus leeway' => [360, 300, null],
        'one second past it' => [361, 300, 'says the person signed in 361 seconds ago, longer than the max_age of 300 seconds'],
        'max_age 0 within the leeway' => [5, 0, null],
        'missing with max_age' => [null, 300, 'has no auth_time, although the login sent max_age 300'],
        'missing without max_age' => [null, null, null],
        'old without max_age' => [86400, null, null],
        'in the future' => [-61, null, 'says the person signed in 61 seconds in the future'],
    ]);

    it('refuses an auth_time that is not a time', function (): void {
        refusedWith(fn () => ($this->verify)(($this->token)(['auth_time' => 'yesterday'])), ErrorCode::TokenClaimInvalid, 'auth_time', 'has a auth_time that is not a time');
    });
});

describe('at_hash', function (): void {
    it('refuses an at_hash that is not a string', function (): void {
        refusedWith(fn () => ($this->verify)(($this->token)(['at_hash' => 1]), new IdTokenExpectations('nonce-1', accessToken: 'access-1')), ErrorCode::IdTokenAtHashMismatch, 'at_hash');
    });

    it('refuses an at_hash made with SHA-256 for an EdDSA token', function (): void {
        $token = ($this->token)(['at_hash' => SigningAlgorithm::RS256->accessTokenHash('access-1')], SigningAlgorithm::EdDSA);

        refusedWith(fn () => ($this->verify)($token, new IdTokenExpectations('nonce-1', accessToken: 'access-1')), ErrorCode::IdTokenAtHashMismatch, 'at_hash');
    });
});

describe('other claims', function (): void {
    it('refuses amr, acr, sid and groups in another form', function (array $claims, string $claim): void {
        refusedWith(fn () => ($this->verify)(($this->token)($claims)), ErrorCode::TokenClaimInvalid, $claim);
    })->with([
        'amr as a string' => [['amr' => 'pwd'], 'amr'],
        'amr with a number' => [['amr' => ['pwd', 1]], 'amr'],
        'acr as a number' => [['acr' => 2], 'acr'],
        'sid as a list' => [['sid' => ['a']], 'sid'],
        'groups as a string' => [['groups' => 'admins'], 'groups'],
        'groups as an object' => [['groups' => ['a' => 'admins']], 'groups'],
    ]);

    it('marks groups unknown when the provider left them out for being too many', function (): void {
        $claims = ($this->verify)(($this->token)(['_claim_names' => ['groups' => 'src1'], '_claim_sources' => ['src1' => ['endpoint' => 'https://graph.example.test']]]));

        expect($claims->groups)->toBeNull()
            ->and($claims->groupsOverage)->toBeTrue();
    });

    it('reads groups from the configured claim, or not at all', function (array $groups, mixed $expected): void {
        useConnection('main', [...config('oidc.connections.main'), 'groups' => $groups]);

        expect(($this->verify)(($this->token)(['groups' => ['a'], 'roles' => ['r']]))->groups)->toBe($expected);
    })->with([
        'another claim' => [['claim' => 'roles'], ['r']],
        'none' => [['source' => 'none'], null],
        'userinfo' => [['source' => 'userinfo'], null],
    ]);
});

describe('Google Workspace (hd)', function (): void {
    beforeEach(function (): void {
        $this->google = new FakeProvider('https://accounts.google.com')->install();
        $this->google->discovery['id_token_signing_alg_values_supported'] = ['RS256'];
        $this->googleToken = fn (array $claims): string => $this->google->idToken(['aud' => 'google-client', ...$claims]);
    });

    it('accepts an account of an allowed domain, in any case', function (string $hd): void {
        expect(($this->verify)(($this->googleToken)(['hd' => $hd]), connection: 'workspace')->tenant)->toBe($hd);
    })->with(['example.com', 'Example.COM']);

    it('refuses a consumer account, which has no hd', function (): void {
        refusedWith(fn () => ($this->verify)(($this->googleToken)([]), connection: 'workspace'), ErrorCode::TenantClaimMissing, 'hd', 'has no hd claim', TenantRejected::class);
    });

    it('refuses an account of another domain', function (mixed $hd, ErrorCode $code): void {
        refusedWith(fn () => ($this->verify)(($this->googleToken)(['hd' => $hd]), connection: 'workspace'), $code, 'hd', '', TenantRejected::class);
    })->with([
        'another domain' => ['example.org', ErrorCode::TenantNotAllowed],
        'a subdomain' => ['evil.example.com', ErrorCode::TenantNotAllowed],
        'an empty hd' => ['', ErrorCode::TenantClaimMissing],
        'a list' => [['example.com'], ErrorCode::TenantClaimMissing],
    ]);

    it('checks the issuer before the tenant', function (): void {
        refusedWith(fn () => ($this->verify)(($this->googleToken)(['iss' => 'accounts.google.com', 'hd' => 'example.org']), connection: 'workspace'), ErrorCode::TokenIssuerMismatch, 'iss', 'names the issuer "accounts.google.com"');
    });
});

describe('Microsoft Entra multi-tenant ({tenantid})', function (): void {
    beforeEach(function (): void {
        $this->entra = FakeProvider::entra()->install();
        useConnection('entra', [
            'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
            'discovery_url' => 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            'client_id' => 'client-1',
            'client_secret' => 'secret-1',
            'redirect_uri' => 'https://app.example.test/oidc/entra/callback',
            'algorithms' => ['RS256'],
            'tenant' => ['claim' => 'tid', 'allowed' => ['11111111-1111-1111-1111-111111111111', '22222222-2222-2222-2222-222222222222']],
        ]);
        $this->tenantOne = '11111111-1111-1111-1111-111111111111';
        $this->entraToken = fn (array $claims = [], ?JWK $key = null): string => $this->entra->idToken(['tid' => $this->tenantOne, ...$claims], key: $key);
    });

    it('accepts a token of an allowed tenant, with the issuer of that tenant', function (): void {
        $claims = ($this->verify)(($this->entraToken)(), connection: 'entra');

        expect($claims->issuer)->toBe('https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0')
            ->and($claims->tenant)->toBe($this->tenantOne);
    });

    it('accepts a tenant id in upper case', function (): void {
        $tid = strtoupper($this->tenantOne);

        expect(($this->verify)(($this->entraToken)(['tid' => $tid]), connection: 'entra')->tenant)->toBe($tid);
    });

    it('refuses a tenant that is not allowed', function (): void {
        $tid = '33333333-3333-3333-3333-333333333333';

        refusedWith(fn () => ($this->verify)(($this->entraToken)(['tid' => $tid]), connection: 'entra'), ErrorCode::TenantNotAllowed, 'tid', 'belongs to the tenant tid "33333333-3333-3333-3333-333333333333"', TenantRejected::class);
    });

    it('refuses a personal Microsoft account unless its tenant is allowed', function (): void {
        refusedWith(fn () => ($this->verify)(($this->entraToken)(['tid' => '9188040d-6c67-4c5b-b112-36a304b66dad']), connection: 'entra'), ErrorCode::TenantNotAllowed, 'tid', '', TenantRejected::class);
    });

    it('refuses a token without tid, or with a tid that is no tenant id', function (mixed $tid, ErrorCode $code, string $message): void {
        refusedWith(fn () => ($this->verify)($this->entra->idToken(['tid' => $tid, 'iss' => 'https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0']), connection: 'entra'), $code, 'tid', $message, TenantRejected::class);
    })->with([
        'no tid' => [null, ErrorCode::TenantClaimMissing, 'has no tid claim'],
        'tid as a number' => [1, ErrorCode::TenantClaimMissing, 'has no tid claim'],
        'tid that is not a GUID' => ['contoso', ErrorCode::TenantNotAllowed, 'is not a tenant id (a GUID)'],
        'tid with a path' => ['11111111-1111-1111-1111-111111111111/v2.0', ErrorCode::TenantNotAllowed, 'is not a tenant id'],
    ]);

    it('refuses an issuer of another tenant than tid names', function (string $iss): void {
        refusedWith(fn () => ($this->verify)(($this->entraToken)(['iss' => $iss]), connection: 'entra'), ErrorCode::TokenIssuerMismatch, 'iss', 'but the connection pins "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v2.0"');
    })->with([
        'an allowed tenant' => ['https://login.microsoftonline.com/22222222-2222-2222-2222-222222222222/v2.0'],
        'the template itself' => ['https://login.microsoftonline.com/{tenantid}/v2.0'],
        'a v1 issuer' => ['https://sts.windows.net/11111111-1111-1111-1111-111111111111/'],
    ]);

    it('refuses a token signed with a key of another issuer', function (): void {
        $this->entra->keys = [FakeProvider::rsaKey('entra-1', values: ['issuer' => 'https://login.microsoftonline.com/{tenantid}/v1.0'])];

        refusedWith(fn () => ($this->verify)(($this->entraToken)(), connection: 'entra'), ErrorCode::TokenIssuerMismatch, 'iss', 'but the key that signed it is for "https://login.microsoftonline.com/11111111-1111-1111-1111-111111111111/v1.0"');
    });

    it('accepts any tenant when the connection allows any on purpose', function (): void {
        useConnection('entra', [...config('oidc.connections.entra'), 'tenant' => ['claim' => 'tid', 'allowed' => ['*']]]);
        $tid = '44444444-4444-4444-4444-444444444444';

        expect(($this->verify)(($this->entraToken)(['tid' => $tid]), connection: 'entra')->tenant)->toBe($tid);
    });
});

describe('a tenant claim of another provider', function (): void {
    it('compares it exactly', function (): void {
        useConnection('main', [...config('oidc.connections.main'), 'tenant' => ['claim' => 'org', 'allowed' => ['Acme']]]);

        expect(($this->verify)(($this->token)(['org' => 'Acme']))->tenant)->toBe('Acme');
        refusedWith(fn () => ($this->verify)(($this->token)(['org' => 'acme'])), ErrorCode::TenantNotAllowed, 'org', '', TenantRejected::class);
    });
});

/**
 * A token signed by the fake provider's RSA key over the raw $payload.
 */
function signedPayload(FakeProvider $provider, string $payload): string
{
    $jws = new JWSBuilder(new AlgorithmManager([SigningAlgorithm::RS256->signatureAlgorithm()]))
        ->create()
        ->withPayload($payload)
        ->addSignature($provider->key('rsa-1'), ['alg' => 'RS256', 'kid' => 'rsa-1'])
        ->build();

    return new CompactSerializer()->serialize($jws, 0);
}

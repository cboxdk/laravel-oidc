<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Cbox\Oidc\Tokens\SigningAlgorithm;
use Closure;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Clock\ClockInterface;

/**
 * An OpenID provider inside the test process. It serves its discovery
 * document and key set through Http::fake(), so every request still passes
 * the package's HTTP client and the SSRF guard, and it signs real tokens with
 * RS256, ES256 and EdDSA keys made by web-token.
 *
 * Every part of what it serves can be changed per test: the document, the
 * keys, the status codes, the Cache-Control header, or the raw body.
 */
final class FakeProvider
{
    public const string ISSUER = 'https://idp.example.test';

    public const string DISCOVERY_URL = self::ISSUER.'/.well-known/openid-configuration';

    public const string JWKS_URL = self::ISSUER.'/oauth/jwks';

    public const string AUTHORIZATION_URL = self::ISSUER.'/oauth/authorize';

    public const string TOKEN_URL = self::ISSUER.'/oauth/token';

    /** A public address the fake DNS gives the provider's host. */
    public const string ADDRESS = '93.184.216.34';

    /** @var array<string, JWK> */
    private static array $keyCache = [];

    /** @var array<string, mixed> */
    public array $discovery;

    /** @var list<JWK> private keys; the key set serves their public halves */
    public array $keys;

    public int $discoveryStatus = 200;

    public int $jwksStatus = 200;

    public ?string $jwksCacheControl = 'public, max-age=3600';

    /** Served instead of the discovery document when set. */
    public ?string $discoveryBody = null;

    /** Served instead of the key set when set. */
    public ?string $jwksBody = null;

    public int $discoveryRequests = 0;

    public int $jwksRequests = 0;

    /**
     * The clients registered at the provider: a secret for the
     * client_secret_* methods, a public key for private_key_jwt, or public
     * for a client without authentication.
     *
     * @var array<string, array{secret?: string, public_key?: JWK, public?: bool}>
     */
    public array $clients = ['client-1' => ['secret' => 'secret-1']];

    /**
     * The audience the provider requires in client assertions; null for the
     * URL of the endpoint the assertion is sent to.
     */
    public ?string $assertionAudience = null;

    /** The algorithm the token endpoint signs ID tokens with. */
    public SigningAlgorithm $idTokenAlgorithm = SigningAlgorithm::RS256;

    public string $discoveryUrl;

    public string $jwksUrl;

    public string $authorizationUrl;

    public string $tokenUrl;

    public string $userinfoUrl;

    public string $revocationUrl;

    public string $endSessionUrl;

    /** Whether a refresh returns a new refresh token, which replaces the old one. */
    public bool $rotateRefreshTokens = true;

    /** Whether a refresh returns a new ID token. */
    public bool $idTokenOnRefresh = true;

    /**
     * Claims that replace those of the ID token a refresh returns (a null
     * claim is left out).
     *
     * @var array<string, mixed>
     */
    public array $refreshClaims = [];

    /**
     * Claims that replace those userinfo returns (a null claim is left out).
     *
     * @var array<string, mixed>
     */
    public array $userInfoClaims = [];

    /**
     * Answers the userinfo endpoint instead of the provider's own logic when set.
     *
     * @var (Closure(Request): PromiseInterface)|null
     */
    public ?Closure $userInfoResponse = null;

    /**
     * Answers the revocation endpoint instead of the provider's own logic when set.
     *
     * @var (Closure(Request): PromiseInterface)|null
     */
    public ?Closure $revocationResponse = null;

    /** @var list<array{form: array<array-key, mixed>, authorization: string|null}> */
    public array $revocationRequests = [];

    /** @var list<string|null> the Authorization header of each userinfo request */
    public array $userInfoRequests = [];

    /**
     * The grants behind each live refresh token: the client and the claims of
     * the login it came from.
     *
     * @var array<string, array{client: string, claims: array<string, mixed>}>
     */
    private array $refreshTokens = [];

    /** @var array<string, array<string, mixed>> the ID token claims behind each live access token */
    private array $accessTokens = [];

    /**
     * Answers the token endpoint instead of the provider's own logic when set.
     *
     * @var (Closure(Request): PromiseInterface)|null
     */
    public ?Closure $tokenResponse = null;

    /** @var list<array{form: array<array-key, mixed>, authorization: string|null}> */
    public array $tokenRequests = [];

    /** @var array<string, mixed>|null the claims of the last client assertion the provider accepted */
    public ?array $lastAssertion = null;

    /** @var array<string, array{client_id: string, redirect_uri: string, challenge: string, nonce: string, claims: array<string, mixed>}> */
    private array $codes = [];

    /**
     * @param  string  $issuer  the issuer the discovery document names; may be an Entra {tenantid} template
     * @param  string|null  $discoveryUrl  default: the issuer's /.well-known/openid-configuration
     * @param  string|null  $endpoints  the base of the endpoint URLs; default: the issuer's /oauth
     */
    public function __construct(
        public string $issuer = self::ISSUER,
        ?string $discoveryUrl = null,
        ?string $endpoints = null,
    ) {
        $endpoints ??= $issuer.'/oauth';
        $this->discoveryUrl = $discoveryUrl ?? $issuer.'/.well-known/openid-configuration';
        $this->jwksUrl = $endpoints.'/jwks';
        $this->authorizationUrl = $endpoints.'/authorize';
        $this->tokenUrl = $endpoints.'/token';
        $this->userinfoUrl = $endpoints.'/userinfo';
        $this->revocationUrl = $endpoints.'/revoke';
        $this->endSessionUrl = $endpoints.'/logout';

        $this->discovery = [
            'issuer' => $issuer,
            'authorization_endpoint' => $this->authorizationUrl,
            'token_endpoint' => $this->tokenUrl,
            'userinfo_endpoint' => $this->userinfoUrl,
            'jwks_uri' => $this->jwksUrl,
            'end_session_endpoint' => $this->endSessionUrl,
            'revocation_endpoint' => $this->revocationUrl,
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'EdDSA'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'private_key_jwt', 'none'],
            'authorization_response_iss_parameter_supported' => true,
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
        ];

        $this->keys = [self::rsaKey('rsa-1'), self::ecKey('ec-1'), self::edKey('ed-1')];
    }

    /**
     * Microsoft Entra's multi-tenant endpoint (organizations): the issuer is
     * the {tenantid} template, and each key names that issuer, as Entra's
     * key set does.
     */
    public static function entra(): self
    {
        $provider = new self(
            'https://login.microsoftonline.com/{tenantid}/v2.0',
            'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
            'https://login.microsoftonline.com/organizations/oauth2/v2.0',
        );
        $provider->keys = [self::rsaKey('entra-1', values: ['issuer' => $provider->issuer])];
        $provider->discovery['id_token_signing_alg_values_supported'] = ['RS256'];
        unset($provider->discovery['authorization_response_iss_parameter_supported']);

        return $provider;
    }

    /**
     * The issuer a token of this provider names: the issuer, or for a
     * {tenantid} template the template with $claims['tid'] filled in.
     *
     * @param  array<string, mixed>  $claims
     */
    public function issuerFor(array $claims = []): string
    {
        if (is_string($claims['iss'] ?? null)) {
            return $claims['iss'];
        }

        return is_string($claims['tid'] ?? null) ? str_replace('{tenantid}', $claims['tid'], $this->issuer) : $this->issuer;
    }

    /**
     * A valid ID token for client-1, signed with $algorithm: iss, sub, aud,
     * iat, exp and nonce, replaced by $claims (a null claim is left out).
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $header
     */
    public function idToken(array $claims = [], SigningAlgorithm $algorithm = SigningAlgorithm::RS256, array $header = [], ?JWK $key = null): string
    {
        $now = $this->now();

        return $this->sign($this->withoutNulls(array_replace([
            'iss' => $this->issuerFor($claims),
            'sub' => 'user-1',
            'aud' => 'client-1',
            'iat' => $now,
            'exp' => $now + 300,
            'nonce' => 'nonce-1',
        ], $claims)), $algorithm, $header, $key);
    }

    /**
     * A valid logout token for client-1 (OpenID Connect Back-Channel Logout
     * 1.0): iss, aud, iat, exp, jti, the back-channel logout event, sub and
     * sid, typed logout+jwt, replaced by $claims (a null claim is left out).
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $header
     */
    public function logoutToken(array $claims = [], SigningAlgorithm $algorithm = SigningAlgorithm::RS256, array $header = [], ?JWK $key = null): string
    {
        $now = $this->now();

        return $this->sign($this->withoutNulls(array_replace([
            'iss' => $this->issuerFor($claims),
            'aud' => 'client-1',
            'iat' => $now,
            'exp' => $now + 120,
            'jti' => bin2hex(random_bytes(16)),
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass],
            'sub' => 'user-1',
            'sid' => 'session-1',
        ], $claims)), $algorithm, array_replace(['typ' => 'logout+jwt'], $header), $key);
    }

    /**
     * A refresh token the provider honours, for the login of $claims, as if
     * it had issued it with the login's tokens.
     *
     * @param  array<string, mixed>  $claims  the ID token claims of that login
     */
    public function issueRefreshToken(array $claims = [], string $client = 'client-1'): string
    {
        $token = bin2hex(random_bytes(16));
        $this->refreshTokens[$token] = ['client' => $client, 'claims' => array_replace(['iss' => $this->issuerFor($claims), 'sub' => 'user-1', 'aud' => $client], $claims)];

        return $token;
    }

    /**
     * An access token the provider honours at userinfo, for the person of
     * $claims.
     *
     * @param  array<string, mixed>  $claims
     */
    public function issueAccessToken(array $claims = []): string
    {
        $token = bin2hex(random_bytes(16));
        $this->accessTokens[$token] = array_replace(['iss' => $this->issuerFor($claims), 'sub' => 'user-1'], $claims);

        return $token;
    }

    /** Whether the refresh token is still live (issued and neither used up by rotation nor revoked). */
    public function refreshTokenLive(string $token): bool
    {
        return isset($this->refreshTokens[$token]);
    }

    /**
     * Answers the provider's URLs from now on. Call after Http::fake() rules
     * of your own, if any; it adds to them.
     */
    public function install(): self
    {
        Http::fake([
            $this->discoveryUrl => function (): PromiseInterface {
                $this->discoveryRequests++;

                return Factory::response($this->discoveryBody ?? $this->json($this->discovery), $this->discoveryStatus, ['Content-Type' => 'application/json']);
            },
            $this->jwksUrl => function (Request $request): PromiseInterface {
                $this->jwksRequests++;
                $headers = ['Content-Type' => 'application/jwk-set+json'];

                if ($this->jwksCacheControl !== null) {
                    $headers['Cache-Control'] = $this->jwksCacheControl;
                }

                return Factory::response($this->jwksBody ?? $this->json($this->jwks()), $this->jwksStatus, $headers);
            },
            $this->tokenUrl => $this->token(...),
            $this->userinfoUrl => $this->userInfo(...),
            $this->revocationUrl => $this->revocation(...),
        ]);

        return $this;
    }

    /**
     * What the provider does when the person signs in and consents: checks
     * the authorization request and answers with the callback's query (code,
     * state and iss). $claims go into the ID token the code is exchanged for.
     *
     * @param  array<string, mixed>  $claims
     * @return array<string, string>
     */
    public function approve(string $authorizationUrl, array $claims = []): array
    {
        $request = $this->authorizationRequest($authorizationUrl);
        $code = bin2hex(random_bytes(16));

        $this->codes[$code] = [
            'client_id' => $request['client_id'],
            'redirect_uri' => $request['redirect_uri'],
            'challenge' => $request['code_challenge'],
            'nonce' => $request['nonce'],
            'claims' => $claims,
        ];

        return ['code' => $code, 'state' => $request['state'], 'iss' => $this->issuerFor($claims)];
    }

    /**
     * What the provider does when the login fails: the callback's query with
     * an OAuth error.
     *
     * @return array<string, string>
     */
    public function deny(string $authorizationUrl, string $error = 'access_denied'): array
    {
        $request = $this->authorizationRequest($authorizationUrl);

        return ['error' => $error, 'error_description' => '<script>alert(1)</script>', 'state' => $request['state'], 'iss' => $this->issuerFor()];
    }

    /**
     * The query of an authorization request, checked as a provider would.
     *
     * @return array<string, string>
     */
    public function authorizationRequest(string $authorizationUrl): array
    {
        if (! str_starts_with($authorizationUrl, $this->authorizationUrl.'?')) {
            throw new \LogicException(sprintf('Not an authorization request of the fake provider: %s', $authorizationUrl));
        }

        parse_str((string) parse_url($authorizationUrl, PHP_URL_QUERY), $query);

        foreach (['response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'nonce', 'code_challenge', 'code_challenge_method'] as $name) {
            if (! isset($query[$name]) || ! is_string($query[$name])) {
                throw new \LogicException(sprintf('The authorization request has no %s.', $name));
            }
        }

        if ($query['response_type'] !== 'code' || $query['code_challenge_method'] !== 'S256' || ! isset($this->clients[$query['client_id']])) {
            throw new \LogicException('The authorization request is not a code request with PKCE S256 from a known client.');
        }

        /** @var array<string, string> $query */
        return $query;
    }

    /**
     * The key set as served: the public halves of the keys.
     *
     * @return array{keys: list<array<string, mixed>>}
     */
    public function jwks(): array
    {
        return ['keys' => array_map(static fn (JWK $key): array => $key->toPublic()->all(), $this->keys)];
    }

    public function key(string $kid): JWK
    {
        foreach ($this->keys as $key) {
            if ($key->get('kid') === $kid) {
                return $key;
            }
        }

        throw new \LogicException(sprintf('The fake provider has no key %s.', $kid));
    }

    /**
     * A compact JWS of $claims, signed with $key (by default the provider's
     * first key for $algorithm). The header gets alg, kid and typ; entries of
     * $header replace them, and a null entry removes one.
     *
     * @param  array<string, mixed>  $claims
     * @param  array<string, mixed>  $header
     */
    public function sign(array $claims, SigningAlgorithm $algorithm = SigningAlgorithm::RS256, array $header = [], ?JWK $key = null): string
    {
        $key ??= $this->firstKeyFor($algorithm);
        $protected = array_filter(
            array_replace(['alg' => $algorithm->value, 'kid' => $key->has('kid') ? $key->get('kid') : null, 'typ' => 'JWT'], $header),
            static fn (mixed $value): bool => $value !== null,
        );

        $jws = new JWSBuilder(new AlgorithmManager([$algorithm->signatureAlgorithm()]))
            ->create()
            ->withPayload($this->json($claims))
            ->addSignature($key, $protected)
            ->build();

        return new CompactSerializer()->serialize($jws, 0);
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public static function rsaKey(string $kid, int $bits = 2048, array $values = []): JWK
    {
        return self::cached("rsa:$bits:$kid", static fn (): JWK => JWKFactory::createRSAKey($bits, ['kid' => $kid, 'use' => 'sig']), $values);
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public static function ecKey(string $kid, string $curve = 'P-256', array $values = []): JWK
    {
        return self::cached("ec:$curve:$kid", static fn (): JWK => JWKFactory::createECKey($curve, ['kid' => $kid, 'use' => 'sig']), $values);
    }

    /**
     * @param  array<string, mixed>  $values
     */
    public static function edKey(string $kid, array $values = []): JWK
    {
        return self::cached("ed:$kid", static fn (): JWK => JWKFactory::createOKPKey('Ed25519', ['kid' => $kid, 'use' => 'sig']), $values);
    }

    private function token(Request $request): PromiseInterface
    {
        $form = $request->data();
        $authorization = $request->header('Authorization')[0] ?? null;
        $this->tokenRequests[] = ['form' => $form, 'authorization' => $authorization];

        if ($this->tokenResponse instanceof Closure) {
            return ($this->tokenResponse)($request);
        }

        $client = $this->authenticate($form, $authorization, $this->tokenUrl);

        if ($client === null) {
            return $this->tokenError(401, 'invalid_client');
        }

        if (($form['grant_type'] ?? null) === 'refresh_token') {
            return $this->refresh($client, $form);
        }

        if (($form['grant_type'] ?? null) !== 'authorization_code') {
            return $this->tokenError(400, 'unsupported_grant_type');
        }

        $code = is_string($form['code'] ?? null) ? $form['code'] : '';
        $issued = $this->codes[$code] ?? null;
        unset($this->codes[$code]);
        $verifier = is_string($form['code_verifier'] ?? null) ? $form['code_verifier'] : '';
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        if ($issued === null || $issued['client_id'] !== $client || $issued['redirect_uri'] !== ($form['redirect_uri'] ?? null) || ! hash_equals($issued['challenge'], $challenge)) {
            return $this->tokenError(400, 'invalid_grant');
        }

        $now = $this->now();
        $accessToken = bin2hex(random_bytes(16));
        $claims = $this->withoutNulls(array_replace([
            'iss' => $this->issuerFor($issued['claims']),
            'sub' => 'user-1',
            'aud' => $client,
            'iat' => $now,
            'exp' => $now + 300,
            'auth_time' => $now,
            'nonce' => $issued['nonce'],
            'at_hash' => $this->idTokenAlgorithm->accessTokenHash($accessToken),
        ], $issued['claims']));
        $refreshToken = bin2hex(random_bytes(16));
        $this->refreshTokens[$refreshToken] = ['client' => $client, 'claims' => $claims];
        $this->accessTokens[$accessToken] = $claims;

        return Factory::response($this->json([
            'access_token' => $accessToken,
            'token_type' => 'Bearer',
            'expires_in' => 3600,
            'refresh_token' => $refreshToken,
            'id_token' => $this->sign($claims, $this->idTokenAlgorithm),
            'scope' => 'openid profile email',
        ]), 200, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
    }

    /**
     * The refresh_token grant: a new access token, a rotated refresh token
     * and a new ID token for the same login, as $rotateRefreshTokens,
     * $idTokenOnRefresh and $refreshClaims say.
     *
     * @param  array<array-key, mixed>  $form
     */
    private function refresh(string $client, array $form): PromiseInterface
    {
        $token = is_string($form['refresh_token'] ?? null) ? $form['refresh_token'] : '';
        $grant = $this->refreshTokens[$token] ?? null;

        if ($grant === null || $grant['client'] !== $client) {
            return $this->tokenError(400, 'invalid_grant');
        }

        $now = $this->now();
        $accessToken = bin2hex(random_bytes(16));
        $original = $grant['claims'];
        $claims = $this->withoutNulls(array_replace(
            array_diff_key($original, ['at_hash' => true]),
            ['iat' => $now, 'exp' => $now + 300, 'at_hash' => $this->idTokenAlgorithm->accessTokenHash($accessToken)],
            $this->refreshClaims,
        ));
        $this->accessTokens[$accessToken] = $claims;
        $response = ['access_token' => $accessToken, 'token_type' => 'Bearer', 'expires_in' => 3600];

        if (is_string($form['scope'] ?? null)) {
            $response['scope'] = $form['scope'];
        }

        if ($this->rotateRefreshTokens) {
            unset($this->refreshTokens[$token]);
            $response['refresh_token'] = bin2hex(random_bytes(16));
            $this->refreshTokens[$response['refresh_token']] = ['client' => $client, 'claims' => $original];
        }

        if ($this->idTokenOnRefresh) {
            $response['id_token'] = $this->sign($claims, $this->idTokenAlgorithm);
        }

        return Factory::response($this->json($response), 200, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store']);
    }

    private function userInfo(Request $request): PromiseInterface
    {
        $authorization = $request->header('Authorization')[0] ?? null;
        $this->userInfoRequests[] = $authorization;

        if ($this->userInfoResponse instanceof Closure) {
            return ($this->userInfoResponse)($request);
        }

        $token = $authorization !== null && str_starts_with($authorization, 'Bearer ') ? substr($authorization, 7) : '';
        $claims = $this->accessTokens[$token] ?? null;

        if ($claims === null) {
            return Factory::response('', 401, ['WWW-Authenticate' => 'Bearer error="invalid_token", error_description="The access token expired"']);
        }

        $document = $this->withoutNulls(array_replace(
            array_intersect_key($claims, array_flip(['sub', 'email', 'email_verified', 'name', 'groups'])),
            $this->userInfoClaims,
        ));

        return Factory::response($this->json($document), 200, ['Content-Type' => 'application/json']);
    }

    private function revocation(Request $request): PromiseInterface
    {
        $form = $request->data();
        $authorization = $request->header('Authorization')[0] ?? null;
        $this->revocationRequests[] = ['form' => $form, 'authorization' => $authorization];

        if ($this->revocationResponse instanceof Closure) {
            return ($this->revocationResponse)($request);
        }

        $client = $this->authenticate($form, $authorization, $this->revocationUrl);

        if ($client === null) {
            return $this->tokenError(401, 'invalid_client');
        }

        $token = is_string($form['token'] ?? null) ? $form['token'] : '';

        // RFC 7009 2.2: a token of another client is not revoked, and the
        // answer is the same 200.
        if (($this->refreshTokens[$token]['client'] ?? null) === $client) {
            unset($this->refreshTokens[$token]);
        }

        unset($this->accessTokens[$token]);

        return Factory::response('', 200);
    }

    /**
     * The client the request authenticates as, or null.
     *
     * @param  array<array-key, mixed>  $form
     */
    private function authenticate(array $form, ?string $authorization, string $endpoint): ?string
    {
        if ($authorization !== null && str_starts_with($authorization, 'Basic ')) {
            [$id, $secret] = array_map(urldecode(...), explode(':', (string) base64_decode(substr($authorization, 6), true), 2) + [1 => '']);

            return isset($this->clients[$id]['secret']) && hash_equals($this->clients[$id]['secret'], $secret) ? $id : null;
        }

        $id = is_string($form['client_id'] ?? null) ? $form['client_id'] : '';
        $client = $this->clients[$id] ?? null;

        if ($client === null) {
            return null;
        }

        if (isset($form['client_secret'])) {
            return isset($client['secret']) && is_string($form['client_secret']) && hash_equals($client['secret'], $form['client_secret']) ? $id : null;
        }

        if (isset($form['client_assertion'])) {
            return ($form['client_assertion_type'] ?? null) === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                && isset($client['public_key']) && is_string($form['client_assertion'])
                && $this->verifyAssertion($form['client_assertion'], $client['public_key'], $id, $endpoint) ? $id : null;
        }

        return ($client['public'] ?? false) === true ? $id : null;
    }

    private function verifyAssertion(string $assertion, JWK $key, string $clientId, string $endpoint): bool
    {
        try {
            $jws = new CompactSerializer()->unserialize($assertion);
            $algorithms = array_map(static fn (SigningAlgorithm $algorithm): SignatureAlgorithm => $algorithm->signatureAlgorithm(), SigningAlgorithm::cases());

            if (! new JWSVerifier(new AlgorithmManager($algorithms))->verifyWithKey($jws, $key, 0)) {
                return false;
            }

            $claims = json_decode((string) $jws->getPayload(), true, 8, JSON_THROW_ON_ERROR);
        } catch (\Throwable) {
            return false;
        }

        if (! is_array($claims)) {
            return false;
        }

        /** @var array<string, mixed> $claims */
        $this->lastAssertion = $claims;
        $now = $this->now();

        return ($claims['iss'] ?? null) === $clientId
            && ($claims['sub'] ?? null) === $clientId
            && ($claims['aud'] ?? null) === ($this->assertionAudience ?? $endpoint)
            && is_int($claims['exp'] ?? null) && $claims['exp'] > $now
            && is_string($claims['jti'] ?? null);
    }

    private function tokenError(int $status, string $error): PromiseInterface
    {
        return Factory::response($this->json(['error' => $error, 'error_description' => 'Details for <b>'.$error.'</b>']), $status, ['Content-Type' => 'application/json']);
    }

    /**
     * @param  array<string, mixed>  $claims
     * @return array<string, mixed>
     */
    private function withoutNulls(array $claims): array
    {
        return array_filter($claims, static fn (mixed $value): bool => $value !== null);
    }

    private function now(): int
    {
        return resolve(ClockInterface::class)->now()->getTimestamp();
    }

    private function firstKeyFor(SigningAlgorithm $algorithm): JWK
    {
        foreach ($this->keys as $key) {
            if (in_array($key->get('kty'), $algorithm->signatureAlgorithm()->allowedKeyTypes(), true)
                && ($algorithm->curve() === null || $key->get('crv') === $algorithm->curve())) {
                return $key;
            }
        }

        throw new \LogicException(sprintf('The fake provider has no key for %s.', $algorithm->value));
    }

    /**
     * Key generation is slow (RSA above all), so each key is made once per
     * test run and reused; $values then adjust a copy.
     *
     * @param  callable(): JWK  $make
     * @param  array<string, mixed>  $values
     */
    private static function cached(string $name, callable $make, array $values): JWK
    {
        $key = self::$keyCache[$name] ??= $make();

        return $values === [] ? $key : new JWK(array_filter(array_replace($key->all(), $values), static fn (mixed $value): bool => $value !== null));
    }

    /**
     * @param  array<array-key, mixed>  $value
     */
    private function json(array $value): string
    {
        return json_encode($value, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    }
}

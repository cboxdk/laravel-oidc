<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Cbox\Oidc\Tokens\SigningAlgorithm;
use GuzzleHttp\Promise\PromiseInterface;
use Illuminate\Http\Client\Factory;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;

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

    public function __construct()
    {
        $this->discovery = [
            'issuer' => self::ISSUER,
            'authorization_endpoint' => self::ISSUER.'/oauth/authorize',
            'token_endpoint' => self::ISSUER.'/oauth/token',
            'userinfo_endpoint' => self::ISSUER.'/oauth/userinfo',
            'jwks_uri' => self::JWKS_URL,
            'end_session_endpoint' => self::ISSUER.'/oauth/logout',
            'revocation_endpoint' => self::ISSUER.'/oauth/revoke',
            'response_types_supported' => ['code'],
            'subject_types_supported' => ['public'],
            'id_token_signing_alg_values_supported' => ['RS256', 'ES256', 'EdDSA'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'client_secret_post', 'none'],
            'authorization_response_iss_parameter_supported' => true,
            'backchannel_logout_supported' => true,
            'backchannel_logout_session_supported' => true,
        ];

        $this->keys = [self::rsaKey('rsa-1'), self::ecKey('ec-1'), self::edKey('ed-1')];
    }

    /**
     * Answers the provider's URLs from now on. Call after Http::fake() rules
     * of your own, if any; it adds to them.
     */
    public function install(): self
    {
        Http::fake([
            self::DISCOVERY_URL => function (): PromiseInterface {
                $this->discoveryRequests++;

                return Factory::response($this->discoveryBody ?? $this->json($this->discovery), $this->discoveryStatus, ['Content-Type' => 'application/json']);
            },
            self::JWKS_URL => function (Request $request): PromiseInterface {
                $this->jwksRequests++;
                $headers = ['Content-Type' => 'application/jwk-set+json'];

                if ($this->jwksCacheControl !== null) {
                    $headers['Cache-Control'] = $this->jwksCacheControl;
                }

                return Factory::response($this->jwksBody ?? $this->json($this->jwks()), $this->jwksStatus, $headers);
            },
        ]);

        return $this;
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

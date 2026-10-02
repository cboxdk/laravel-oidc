<?php

declare(strict_types=1);

namespace Cbox\Oidc\Keys;

use Cbox\Oidc\Exceptions\SigningKeyNotFound;
use Cbox\Oidc\Exceptions\SigningKeyUnsuitable;
use Cbox\Oidc\Support\CarbonClock;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Jose\Component\Core\JWK;
use Jose\Component\Core\Util\Base64UrlSafe;
use Jose\Component\KeyManagement\Analyzer\ES256KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES384KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\ES512KeyAnalyzer;
use Jose\Component\KeyManagement\Analyzer\KeyAnalyzerManager;
use Jose\Component\KeyManagement\Analyzer\Message;
use Jose\Component\KeyManagement\Analyzer\RsaAnalyzer;
use Psr\Clock\ClockInterface;
use Throwable;

/**
 * Picks the one key of a key set that may verify a token, from the token
 * header's alg and kid. It never tries keys one by one.
 *
 * - With a kid, the key with that kid; an unknown kid is
 *   {@see SigningKeyNotFound} (worth a refetch).
 * - Without a kid, the single key that fits the algorithm; none or several is
 *   {@see SigningKeyNotFound}.
 * - A key fits when its use is sig or absent, its key_ops (if any) allow
 *   verify, its alg (if any) is the token's, its kty is one web-token's
 *   algorithm takes, its crv is the algorithm's curve, and web-token's key
 *   analyzers find no high-severity flaw: RSA at least 2048 bits with a public
 *   exponent of at least 65537, EC points on the curve. A key marked revoked,
 *   or outside its exp and nbf, does not fit either. A named key that does
 *   not fit is {@see SigningKeyUnsuitable}.
 *
 * Header members that carry or point to a key (jwk, jku, x5u, x5c) are never
 * consulted: keys come from the provider's key set only.
 */
final readonly class KeySelector
{
    private KeyAnalyzerManager $analyzers;

    public function __construct(private ClockInterface $clock = new CarbonClock)
    {
        $this->analyzers = new KeyAnalyzerManager;
        $this->analyzers->add(new RsaAnalyzer);
        $this->analyzers->add(new ES256KeyAnalyzer);
        $this->analyzers->add(new ES384KeyAnalyzer);
        $this->analyzers->add(new ES512KeyAnalyzer);
    }

    /**
     * @throws SigningKeyNotFound
     * @throws SigningKeyUnsuitable
     */
    public function select(KeySet $keys, SigningAlgorithm $algorithm, ?string $kid, string $connection): JWK
    {
        if ($kid === null) {
            $suitable = array_values(array_filter($keys->keys, fn (JWK $key): bool => $this->problems($key, $algorithm) === []));

            return match (count($suitable)) {
                0 => throw SigningKeyNotFound::noSuitableKey($connection, $algorithm->value),
                1 => $suitable[0],
                default => throw SigningKeyNotFound::ambiguous($connection, $algorithm->value, count($suitable)),
            };
        }

        $named = $keys->withKid($kid);

        if ($named === []) {
            throw SigningKeyNotFound::unknownKid($connection, $kid);
        }

        $suitable = [];
        $problems = [];

        foreach ($named as $key) {
            $found = $this->problems($key, $algorithm);

            if ($found === []) {
                $suitable[] = $key;
            } else {
                array_push($problems, ...$found);
            }
        }

        if (count($suitable) > 1) {
            throw SigningKeyNotFound::ambiguous($connection, $algorithm->value, count($suitable));
        }

        if ($suitable === []) {
            /** @var non-empty-list<string> $problems */
            throw SigningKeyUnsuitable::because($connection, $kid, $algorithm->value, array_values(array_unique($problems)));
        }

        return $suitable[0];
    }

    /**
     * Why $key may not verify a token signed with $algorithm; empty when it may.
     *
     * @return list<string>
     */
    public function problems(JWK $key, SigningAlgorithm $algorithm): array
    {
        $kty = $key->get('kty');
        $allowedTypes = $algorithm->signatureAlgorithm()->allowedKeyTypes();

        if (! in_array($kty, $allowedTypes, true)) {
            return [sprintf('it is a %s key, and %s takes %s', is_string($kty) ? $kty : 'malformed', $algorithm->value, implode(' or ', $allowedTypes))];
        }

        $problems = [];

        if ($key->has('use') && $key->get('use') !== 'sig') {
            $problems[] = 'its use is not sig';
        }

        if ($key->has('key_ops') && (! is_array($key->get('key_ops')) || ! in_array('verify', $key->get('key_ops'), true))) {
            $problems[] = 'its key_ops do not allow verify';
        }

        if ($key->has('alg') && $key->get('alg') !== $algorithm->value) {
            $problems[] = sprintf('it is marked for alg %s', is_string($key->get('alg')) ? $key->get('alg') : 'malformed');
        }

        array_push($problems, ...$this->validity($key));

        $curve = $algorithm->curve();

        if ($curve !== null && $key->get('crv') !== $curve) {
            $problems[] = sprintf('its curve is not %s', $curve);

            return $problems;
        }

        return [...$problems, ...$this->flaws($key, $algorithm)];
    }

    /**
     * Whether the key is withdrawn or outside its validity: keys of an
     * OpenID Federation key set may carry exp, nbf and revoked. A provider
     * that publishes neither is not affected.
     *
     * @return list<string>
     */
    private function validity(JWK $key): array
    {
        $now = $this->clock->now()->getTimestamp();
        $problems = [];

        if ($key->has('revoked')) {
            $problems[] = 'it is marked revoked';
        }

        foreach (['exp' => 'it expired at %s', 'nbf' => 'it is not valid before %s'] as $member => $problem) {
            if (! $key->has($member)) {
                continue;
            }

            $value = $key->get($member);

            if (! is_int($value) && ! is_float($value)) {
                $problems[] = sprintf('its %s is not a time', $member);
            } elseif ($member === 'exp' ? $value <= $now : $value > $now) {
                $problems[] = sprintf($problem, gmdate('Y-m-d\\TH:i:s\\Z', (int) $value));
            }
        }

        return $problems;
    }

    /**
     * Flaws in the key material itself, found by web-token's analyzers and,
     * for Ed25519, by the length of x.
     *
     * @return list<string>
     */
    private function flaws(JWK $key, SigningAlgorithm $algorithm): array
    {
        try {
            if ($algorithm === SigningAlgorithm::EdDSA) {
                $x = $key->has('x') ? $key->get('x') : null;

                return is_string($x) && strlen(Base64UrlSafe::decodeNoPadding($x)) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES
                    ? []
                    : ['its x is not a 32-byte Ed25519 public key'];
            }

            $flaws = [];

            foreach ($this->analyzers->analyze($key)->all() as $message) {
                if ($message->getSeverity() === Message::SEVERITY_HIGH) {
                    $flaws[] = lcfirst(rtrim(str_replace('Invalid key. ', '', $message->getMessage()), '.'));
                }
            }

            return $flaws;
        } catch (Throwable) {
            return ['its key material is malformed'];
        }
    }
}

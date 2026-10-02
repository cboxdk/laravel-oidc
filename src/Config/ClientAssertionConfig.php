<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Keys\KeySelector;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use SensitiveParameter;
use Throwable;

/**
 * The private key and settings a connection with client_auth private_key_jwt
 * signs its client assertions with (RFC 7523, OpenID Connect Core 9).
 *
 * The key is read once, when the configuration is parsed, from PEM text or a
 * PEM file, and must be a private RSA, EC or Ed25519 key that fits the
 * algorithm: RSA at least 2048 bits, EC on the algorithm's curve.
 */
readonly class ClientAssertionConfig
{
    /**
     * Header members a client assertion's own settings control, which
     * headers may not set.
     */
    public const array RESERVED_HEADERS = ['alg', 'b64', 'crit', 'enc', 'jku', 'jwk', 'kid', 'typ', 'x5u', 'zip'];

    /**
     * @param  array<string, string>  $headers
     */
    public function __construct(
        #[SensitiveParameter] public JWK $key,
        public SigningAlgorithm $algorithm,
        public ?string $keyId,
        public AssertionAudience $audience,
        public array $headers,
        public int $lifetimeSeconds,
    ) {}

    public static function fromConfig(ConfigReader $config, bool $templatedIssuer): self
    {
        $algorithm = SigningAlgorithm::tryFrom($config->string('algorithm', SigningAlgorithm::RS256->value));

        if ($algorithm === null) {
            throw InvalidConfiguration::at($config->key('algorithm'), 'is not a supported signing algorithm', sprintf('Set %s to one of %s.', $config->key('algorithm'), implode(', ', SigningAlgorithm::names())));
        }

        $audience = AssertionAudience::tryFrom($config->string('audience', AssertionAudience::TokenEndpoint->value));

        if ($audience === null) {
            throw InvalidConfiguration::at($config->key('audience'), 'is not a known assertion audience', sprintf('Set %s to token_endpoint or issuer.', $config->key('audience')));
        }

        if ($audience === AssertionAudience::Issuer && $templatedIssuer) {
            throw InvalidConfiguration::at($config->key('audience'), 'cannot be issuer when the issuer uses {tenantid}', sprintf('Set %s to token_endpoint; a templated issuer names no single provider.', $config->key('audience')));
        }

        $headers = $config->stringMap('headers');

        foreach (array_keys($headers) as $name) {
            if (in_array(strtolower($name), self::RESERVED_HEADERS, true)) {
                throw InvalidConfiguration::at(sprintf('%s.%s', $config->key('headers'), $name), 'is set by the package itself', sprintf('Remove %s from %s; set the key id with key_id.', $name, $config->key('headers')));
            }
        }

        return new self(
            key: self::key($config, $algorithm),
            algorithm: $algorithm,
            keyId: $config->nullableString('key_id'),
            audience: $audience,
            headers: $headers,
            lifetimeSeconds: $config->int('lifetime_seconds', 60, 10, 600),
        );
    }

    /**
     * Keeps the private key out of dumps and logs.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'key' => '[redacted]',
            'algorithm' => $this->algorithm,
            'keyId' => $this->keyId,
            'audience' => $this->audience,
            'headers' => $this->headers,
            'lifetimeSeconds' => $this->lifetimeSeconds,
        ];
    }

    private static function key(ConfigReader $config, SigningAlgorithm $algorithm): JWK
    {
        $hasText = $config->has('key');
        $hasPath = $config->has('key_path');

        if ($hasText === $hasPath) {
            throw InvalidConfiguration::at($config->key('key'), $hasText ? 'is set together with key_path' : 'is required for client_auth private_key_jwt', sprintf('Set exactly one of %s (the PEM text) and %s (a PEM file).', $config->key('key'), $config->key('key_path')));
        }

        $source = $hasText ? $config->key('key') : $config->key('key_path');

        // OpenSSL asks for the passphrase on the terminal when an encrypted
        // key arrives with none, which would hang a queue worker; an empty
        // passphrase makes it fail instead.
        $passphrase = $config->nullableString('passphrase') ?? '';
        $path = $hasPath ? self::localFile($config) : null;

        try {
            $key = $path === null
                ? JWKFactory::createFromKey($config->string('key'), $passphrase)
                : JWKFactory::createFromKeyFile($path, $passphrase);
        } catch (Throwable) {
            throw InvalidConfiguration::at($source, 'is not a PEM private key the package can read, or its passphrase is wrong', sprintf('Set %s to an RSA, EC or Ed25519 private key in PEM form, and %s when it is encrypted.', $source, $config->key('passphrase')));
        }

        if (! $key->has('d')) {
            throw InvalidConfiguration::at($source, 'is a public key', sprintf('Set %s to the private key; the provider holds the public half.', $source));
        }

        $problems = new KeySelector()->problems($key->toPublic(), $algorithm);

        if ($problems !== []) {
            throw InvalidConfiguration::at($source, sprintf('cannot sign %s: %s', $algorithm->value, implode('; ', $problems)), sprintf('Use a key that fits %s, or set %s to the algorithm of your key.', $algorithm->value, $config->key('algorithm')));
        }

        return $key;
    }

    /**
     * The key file's path, refused when it names a stream wrapper (http://,
     * phar:, data: and the like) rather than a local file.
     */
    private static function localFile(ConfigReader $config): string
    {
        $path = $config->string('key_path');

        if (preg_match('/^[A-Za-z][A-Za-z0-9+.-]+:/', $path) === 1 || ! is_file($path) || ! is_readable($path)) {
            throw InvalidConfiguration::at($config->key('key_path'), 'names no readable local file', sprintf('Set %s to the path of a PEM file this process can read.', $config->key('key_path')));
        }

        return $path;
    }
}

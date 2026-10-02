<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Keys\SigningKeys;
use Cbox\Oidc\Support\Base64Url;
use Cbox\Oidc\Support\StrictJson;
use Jose\Component\Checker\AlgorithmChecker;
use Jose\Component\Checker\InvalidHeaderException;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use JsonException;
use SensitiveParameter;
use Throwable;

/**
 * Reads a compact JWS and verifies its signature with the provider's key, in
 * this order:
 *
 * 1. at most {@see self::MAX_LENGTH} bytes, three base64url parts (Compact
 *    Serialization only: a JWE or a JSON-serialized JWS is refused, so there
 *    is no unprotected header for an alg to hide in);
 * 2. the header is a JSON object with unique keys, without crit or b64, and
 *    with a typ the token's kind accepts;
 * 3. alg is one of the connection's algorithms that the provider also lists,
 *    checked by web-token's AlgorithmChecker on the protected header (none and
 *    HS* cannot be configured, so they never pass);
 * 4. the key comes from the provider's key set by kid ({@see SigningKeys});
 *    header members that carry or point to a key (jwk, jku, x5u, x5c) are
 *    never used;
 * 5. web-token's JWSVerifier checks the signature, with an algorithm manager
 *    that holds only that one algorithm;
 * 6. the payload is a JSON object with unique keys.
 *
 * @internal
 */
final readonly class SignedJwtReader
{
    /** The longest token read. */
    public const int MAX_LENGTH = 16384;

    public function __construct(private SigningKeys $keys) {}

    /**
     * @throws TokenRejected
     * @throws OidcException when the provider's keys cannot be loaded or none fits
     */
    public function read(ConnectionConfig $connection, ProviderMetadata $metadata, TokenKind $kind, #[SensitiveParameter] string $token): SignedJwt
    {
        $name = $connection->name;

        if (strlen($token) > self::MAX_LENGTH) {
            throw TokenRejected::malformed($kind, $name, sprintf('is %d bytes long, more than the %d the package reads', strlen($token), self::MAX_LENGTH));
        }

        if (preg_match('/^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/D', $token, $parts) !== 1) {
            throw TokenRejected::malformed($kind, $name, substr_count($token, '.') === 4
                ? 'is encrypted (a JWE), which the package does not read'
                : 'is not a compact JWS of three base64url parts');
        }

        $header = $this->header($kind, $name, $parts[1]);
        $algorithm = $this->algorithm($kind, $connection, $metadata, $header);
        $kid = $header['kid'] ?? null;

        if ($kid !== null && (! is_string($kid) || $kid === '' || strlen($kid) > 1024)) {
            throw TokenRejected::malformed($kind, $name, 'has a kid that is not a non-empty string', 'kid');
        }

        $key = $this->keys->find($connection, $algorithm, $kid);

        try {
            $jws = new CompactSerializer()->unserialize($token);
            $verified = new JWSVerifier(new AlgorithmManager([$algorithm->signatureAlgorithm()]))->verifyWithKey($jws, $key, 0);
        } catch (Throwable) {
            $verified = false;
        }

        if (! $verified) {
            $keyId = $key->has('kid') ? $key->get('kid') : null;

            throw TokenRejected::signatureInvalid($kind, $name, is_string($keyId) ? sprintf('"%s"', $keyId) : 'without a kid');
        }

        return new SignedJwt($header, $this->claims($kind, $name, $parts[2]), $algorithm, $key);
    }

    /**
     * @return array<string, mixed>
     */
    private function header(TokenKind $kind, string $connection, string $encoded): array
    {
        $header = $this->object($encoded);

        if ($header === null) {
            throw TokenRejected::malformed($kind, $connection, 'has a header that is not a JSON object with unique keys');
        }

        // crit names members the recipient must understand (RFC 7515 4.1.11);
        // the package understands none. b64 (RFC 7797) changes what is signed.
        foreach (['crit', 'b64'] as $member) {
            if (array_key_exists($member, $header)) {
                throw TokenRejected::malformed($kind, $connection, sprintf('has the header member %s, which the package does not support', $member), $member);
            }
        }

        $type = $header['typ'] ?? null;

        if ($type !== null && ! is_string($type)) {
            throw TokenRejected::malformed($kind, $connection, 'has a typ that is not a string', 'typ');
        }

        if (! $kind->acceptsType($type)) {
            throw TokenRejected::typeInvalid($kind, $connection, (string) $type);
        }

        return $header;
    }

    /**
     * @param  array<string, mixed>  $header
     */
    private function algorithm(TokenKind $kind, ConnectionConfig $connection, ProviderMetadata $metadata, array $header): SigningAlgorithm
    {
        $allowed = array_map(static fn (SigningAlgorithm $algorithm): string => $algorithm->value, $metadata->signingAlgorithms);
        $alg = $header['alg'] ?? null;

        try {
            // A compact JWS has only a protected header, so protectedHeaderOnly
            // holds by construction; web-token decides whether alg is allowed.
            new AlgorithmChecker($allowed, true)->checkHeader($alg);
        } catch (InvalidHeaderException) {
            throw TokenRejected::algorithmNotAllowed($kind, $connection->name, is_string($alg) ? $alg : null, $allowed);
        }

        /** @var string $alg */
        return SigningAlgorithm::from($alg);
    }

    /**
     * @return array<string, mixed>
     */
    private function claims(TokenKind $kind, string $connection, string $encoded): array
    {
        $claims = $this->object($encoded);

        if ($claims === null) {
            throw TokenRejected::malformed($kind, $connection, 'has a payload that is not a JSON object with unique keys');
        }

        return $claims;
    }

    /**
     * @return array<string, mixed>|null
     */
    private function object(string $encoded): ?array
    {
        $json = Base64Url::decode($encoded);

        if ($json === null) {
            return null;
        }

        try {
            $value = StrictJson::decodeObject($json, 16);
        } catch (JsonException) {
            return null;
        }

        if ($value !== [] && array_is_list($value)) {
            return null;
        }

        /** @var array<string, mixed> $value */
        return $value;
    }
}

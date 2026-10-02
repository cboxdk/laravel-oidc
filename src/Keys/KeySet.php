<?php

declare(strict_types=1);

namespace Cbox\Oidc\Keys;

use Cbox\Oidc\Exceptions\KeySetInvalid;
use InvalidArgumentException;
use Jose\Component\Core\JWK;

/**
 * A provider's public signing keys, parsed by web-token from the document at
 * jwks_uri (RFC 7517 5).
 *
 * Keys without a kty, and keys web-token cannot read, are left out, as RFC
 * 7517 5 asks. Private members a provider publishes by mistake are dropped.
 * Whether a key may verify a given token is decided later, by
 * {@see KeySelector}.
 */
final readonly class KeySet
{
    /** At most this many keys are read from a key set. */
    public const int MAX_KEYS = 100;

    /**
     * @param  list<JWK>  $keys
     */
    public function __construct(public array $keys) {}

    /**
     * @param  array<array-key, mixed>  $document
     *
     * @throws KeySetInvalid
     */
    public static function fromDocument(array $document, string $connection, string $url): self
    {
        $entries = $document['keys'] ?? null;

        if (! is_array($entries) || ! array_is_list($entries)) {
            throw KeySetInvalid::because($connection, $url, 'has no "keys" list');
        }

        if (count($entries) > self::MAX_KEYS) {
            throw KeySetInvalid::because($connection, $url, sprintf('has %d keys, more than the %d the package reads', count($entries), self::MAX_KEYS));
        }

        $keys = [];

        foreach ($entries as $index => $entry) {
            if (! is_array($entry) || ($entry !== [] && array_is_list($entry))) {
                throw KeySetInvalid::because($connection, $url, sprintf('has an entry %d that is not a JSON object', $index));
            }

            if (! is_string($entry['kty'] ?? null)) {
                continue;
            }

            try {
                /** @var array<string, mixed> $entry */
                $keys[] = new JWK($entry)->toPublic();
            } catch (InvalidArgumentException) {
                continue;
            }
        }

        return new self($keys);
    }

    /**
     * The keys whose kid is $kid.
     *
     * @return list<JWK>
     */
    public function withKid(string $kid): array
    {
        return array_values(array_filter($this->keys, static fn (JWK $key): bool => $key->has('kid') && $key->get('kid') === $kid));
    }
}

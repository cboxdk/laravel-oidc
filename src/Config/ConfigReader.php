<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Support\Url;

/**
 * Reads typed values out of one array of config/oidc.php and names the full key
 * of any value it refuses. The only place the package touches the raw array.
 *
 * @internal
 */
readonly class ConfigReader
{
    /**
     * @param  array<array-key, mixed>  $values
     */
    public function __construct(
        private array $values,
        private string $path,
    ) {}

    /**
     * Reads $value as an array of config/oidc.php found at $path.
     */
    public static function of(mixed $value, string $path): self
    {
        if (! is_array($value)) {
            throw InvalidConfiguration::at($path, 'must be an array', sprintf('Set %s to an array, as the published config/oidc.php shows.', $path));
        }

        return new self($value, $path);
    }

    public function key(string $key): string
    {
        return $this->path.'.'.$key;
    }

    public function has(string $key): bool
    {
        return array_key_exists($key, $this->values) && $this->values[$key] !== null;
    }

    /**
     * The keys of this array that are strings, in order. Configuration keys
     * that are not strings are refused.
     *
     * @return list<string>
     */
    public function names(): array
    {
        $names = [];

        foreach (array_keys($this->values) as $name) {
            if (! is_string($name)) {
                throw InvalidConfiguration::at($this->key((string) $name), 'is not named', sprintf('Give every entry of %s a name as its key.', $this->path));
            }

            $names[] = $name;
        }

        return $names;
    }

    public function child(string $key): self
    {
        return self::of($this->values[$key] ?? null, $this->key($key));
    }

    public function string(string $key, ?string $default = null): string
    {
        $value = $this->values[$key] ?? $default;

        if (! is_string($value) || trim($value) === '') {
            throw InvalidConfiguration::at($this->key($key), 'must be a non-empty string', sprintf('Set %s, usually from the environment.', $this->key($key)));
        }

        return $value;
    }

    public function nullableString(string $key): ?string
    {
        return $this->has($key) ? $this->string($key) : null;
    }

    public function int(string $key, int $default, int $min, int $max): int
    {
        $value = $this->values[$key] ?? $default;

        if (is_string($value) && preg_match('/^-?\d+$/D', $value) === 1) {
            $value = (int) $value;
        }

        if (! is_int($value) || $value < $min || $value > $max) {
            throw InvalidConfiguration::at($this->key($key), sprintf('must be a whole number from %d to %d', $min, $max), sprintf('Set %s to a whole number from %d to %d.', $this->key($key), $min, $max));
        }

        return $value;
    }

    public function nullableInt(string $key, int $min, int $max): ?int
    {
        return $this->has($key) ? $this->int($key, $min, $min, $max) : null;
    }

    public function bool(string $key, bool $default): bool
    {
        $value = $this->values[$key] ?? $default;

        if (is_string($value) && in_array(strtolower($value), ['true', 'false', '1', '0'], true)) {
            $value = in_array(strtolower($value), ['true', '1'], true);
        }

        if (! is_bool($value)) {
            throw InvalidConfiguration::at($this->key($key), 'must be true or false', sprintf('Set %s to true or false.', $this->key($key)));
        }

        return $value;
    }

    public function float(string $key, float $default, float $min, float $max): float
    {
        $value = $this->values[$key] ?? $default;

        if (is_string($value) && is_numeric($value)) {
            $value = (float) $value;
        }

        if (is_int($value)) {
            $value = (float) $value;
        }

        if (! is_float($value) || $value < $min || $value > $max) {
            throw InvalidConfiguration::at($this->key($key), sprintf('must be a number from %s to %s', $min, $max), sprintf('Set %s to a number from %s to %s.', $this->key($key), $min, $max));
        }

        return $value;
    }

    /**
     * @param  list<string>  $default
     * @return list<string>
     */
    public function stringList(string $key, array $default): array
    {
        $value = $this->values[$key] ?? $default;

        if (! is_array($value) || ! array_is_list($value)) {
            throw InvalidConfiguration::at($this->key($key), 'must be a list of strings', sprintf('Set %s to a list such as [\'a\', \'b\'].', $this->key($key)));
        }

        $strings = [];

        foreach ($value as $index => $item) {
            if (! is_string($item) || trim($item) === '') {
                throw InvalidConfiguration::at(sprintf('%s.%d', $this->key($key), $index), 'must be a non-empty string', sprintf('Remove or correct entry %d of %s.', $index, $this->key($key)));
            }

            $strings[] = $item;
        }

        return $strings;
    }

    /**
     * @return array<string, string>
     */
    public function stringMap(string $key): array
    {
        $value = $this->values[$key] ?? [];

        if (! is_array($value) || ($value !== [] && array_is_list($value))) {
            throw InvalidConfiguration::at($this->key($key), 'must be a map of names to strings', sprintf('Set %s to an array such as [\'name\' => \'value\'].', $this->key($key)));
        }

        $map = [];

        foreach ($value as $name => $item) {
            if (! is_string($name) || ! is_string($item)) {
                throw InvalidConfiguration::at(sprintf('%s.%s', $this->key($key), $name), 'must be a string', sprintf('Set every value of %s to a string.', $this->key($key)));
            }

            $map[$name] = $item;
        }

        return $map;
    }

    /**
     * An https URL without user info or fragment; with $insecureHttp, plain
     * http too (allow_insecure_http, local development only).
     */
    public function httpsUrl(string $key, ?string $value = null, bool $insecureHttp = false): string
    {
        return $this->url($key, $value ?? $this->string($key), $insecureHttp ? ['http', 'https'] : ['https']);
    }

    /**
     * An absolute https URL without user info or fragment, for browser
     * redirect targets such as the redirect URI. Plain http is accepted only
     * on a local host ({@see Url::isLocalHost()}), for local development: on
     * any other host the code and state would cross the network unencrypted.
     */
    public function browserUrl(string $key): string
    {
        $value = $this->url($key, $this->string($key), ['http', 'https']);
        $parts = (array) parse_url($value);

        if (strtolower((string) ($parts['scheme'] ?? '')) === 'http' && ! Url::isLocalHost((string) ($parts['host'] ?? ''))) {
            throw InvalidConfiguration::at($this->key($key), 'uses http on a host that is not local', sprintf('Set %s to an https URL and register that one at the provider. http is accepted only on localhost, 127.0.0.1, [::1] and names below .localhost or .test.', $this->key($key)));
        }

        return $value;
    }

    /**
     * @param  list<string>  $schemes
     */
    private function url(string $key, string $value, array $schemes): string
    {
        $parts = parse_url($value);
        $scheme = is_array($parts) && isset($parts['scheme']) ? strtolower($parts['scheme']) : null;

        if (! is_array($parts) || $scheme === null || ! in_array($scheme, $schemes, true) || ! isset($parts['host']) || $parts['host'] === '') {
            throw InvalidConfiguration::at($this->key($key), sprintf('must be an absolute %s URL', implode(' or ', $schemes)), sprintf('Set %s to a full URL starting with %s://.', $this->key($key), $schemes[count($schemes) - 1]));
        }

        if (isset($parts['user']) || isset($parts['pass']) || isset($parts['fragment'])) {
            throw InvalidConfiguration::at($this->key($key), 'must not carry user info or a fragment', sprintf('Remove the user:password@ part and any #fragment from %s.', $this->key($key)));
        }

        return $value;
    }
}

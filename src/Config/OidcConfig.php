<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Support\Url;

/**
 * The whole of config/oidc.php, parsed and checked.
 *
 * The container builds it once, from config('oidc'), the first time the
 * package needs it. Every connection is checked then, so one bad connection
 * fails loudly even when code only uses another.
 */
readonly class OidcConfig
{
    /**
     * @param  array<string, ConnectionConfig>  $connections
     */
    public function __construct(
        public string $default,
        public array $connections,
        public HttpConfig $http = new HttpConfig,
        public CacheConfig $cache = new CacheConfig,
        public FlowConfig $flow = new FlowConfig,
    ) {}

    /**
     * @param  bool  $development  whether the application runs in a local or testing environment; only then may a connection set allow_insecure_http
     */
    public static function fromArray(mixed $values, bool $development = false): self
    {
        $config = ConfigReader::of($values, 'oidc');
        $connectionsConfig = $config->child('connections');
        $connections = [];
        $callbacks = [];

        foreach ($connectionsConfig->names() as $name) {
            if (preg_match('/^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/D', $name) !== 1) {
                throw InvalidConfiguration::at($connectionsConfig->key($name), 'is not a valid connection name', 'Name connections with letters, digits, dots, dashes and underscores, at most 64 characters.');
            }

            $connection = ConnectionConfig::fromConfig($name, $connectionsConfig->child($name), $development);
            $callback = Url::callbackTarget($connection->redirectUri);

            // A callback shared by two connections cannot tell their responses
            // apart, which is what a mix-up attack needs when the provider
            // sends no iss parameter (RFC 9207).
            if (isset($callbacks[$callback])) {
                throw InvalidConfiguration::at(
                    $connectionsConfig->key($name).'.redirect_uri',
                    sprintf('is the redirect_uri of connection "%s" too', $callbacks[$callback]),
                    sprintf('Give every connection its own callback URL, such as /oidc/%s/callback, with its own route, and register that URL at the provider.', $name),
                );
            }

            $callbacks[$callback] = $name;
            $connections[$name] = $connection;
        }

        if ($connections === []) {
            throw InvalidConfiguration::at('oidc.connections', 'defines no connection', 'Add at least one connection under connections in config/oidc.php.');
        }

        $default = $config->string('default', array_key_first($connections));

        if (! array_key_exists($default, $connections)) {
            throw InvalidConfiguration::at('oidc.default', sprintf('names "%s", which is not a configured connection', $default), sprintf('Set oidc.default (OIDC_CONNECTION) to one of %s.', implode(', ', array_keys($connections))));
        }

        $http = $config->has('http') ? HttpConfig::fromConfig($config->child('http')) : new HttpConfig;

        if (array_any($connections, static fn (ConnectionConfig $connection): bool => $connection->allowInsecureHttp)) {
            $http = $http->withInsecureHttp();
        }

        return new self(
            $default,
            $connections,
            $http,
            $config->has('cache') ? CacheConfig::fromConfig($config->child('cache')) : new CacheConfig,
            $config->has('flow') ? FlowConfig::fromConfig($config->child('flow')) : new FlowConfig,
        );
    }

    /**
     * The named connection, or the default one when $name is null.
     *
     * @throws UnknownConnection
     */
    public function connection(?string $name = null): ConnectionConfig
    {
        $name ??= $this->default;

        return $this->connections[$name] ?? throw UnknownConnection::named($name, $this->names());
    }

    /**
     * @return list<string>
     */
    public function names(): array
    {
        return array_keys($this->connections);
    }
}

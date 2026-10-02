<?php

declare(strict_types=1);

use Cbox\Oidc\Config\CacheConfig;
use Cbox\Oidc\Config\ClientAuthMethod;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\FlowConfig;
use Cbox\Oidc\Config\GroupsSource;
use Cbox\Oidc\Config\HttpConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tokens\SigningAlgorithm;

/**
 * @param  array<string, mixed>  $connection
 * @param  array<string, mixed>  $extra
 */
function oidcConfig(array $connection, array $extra = []): OidcConfig
{
    return OidcConfig::fromArray(array_replace(['connections' => ['main' => $connection]], $extra));
}

/**
 * @param  array<string, mixed>  $connection
 */
function refusal(array $connection): InvalidConfiguration
{
    try {
        oidcConfig($connection);
    } catch (InvalidConfiguration $exception) {
        return $exception;
    }

    throw new RuntimeException('The configuration was accepted.');
}

it('fills every default from a minimal connection', function (): void {
    $connection = oidcConfig(ConnectionFixtures::minimal())->connection();

    expect($connection->name)->toBe('main')
        ->and($connection->issuer)->toBe('https://idp.example.test')
        ->and($connection->discoveryUrl)->toBe('https://idp.example.test/.well-known/openid-configuration')
        ->and($connection->clientAuth)->toBe(ClientAuthMethod::ClientSecretBasic)
        ->and($connection->scopes)->toBe(['openid', 'profile', 'email'])
        ->and($connection->algorithms)->toBe([SigningAlgorithm::RS256, SigningAlgorithm::RS384, SigningAlgorithm::RS512, SigningAlgorithm::PS256, SigningAlgorithm::PS384, SigningAlgorithm::PS512, SigningAlgorithm::ES256, SigningAlgorithm::ES384, SigningAlgorithm::ES512, SigningAlgorithm::EdDSA])
        ->and($connection->leewaySeconds)->toBe(60)
        ->and($connection->maxTokenAgeSeconds)->toBe(600)
        ->and($connection->maxAge)->toBeNull()
        ->and($connection->tenant)->toBeNull()
        ->and($connection->groups->source)->toBe(GroupsSource::IdToken)
        ->and($connection->groups->claim)->toBe('groups')
        ->and($connection->postLogoutRedirectUri)->toBeNull()
        ->and($connection->authorizationParameters)->toBe([]);
});

it('reads the published config file as shipped once the environment is set', function (): void {
    $values = require __DIR__.'/../../../config/oidc.php';
    $values['connections']['main'] = array_replace($values['connections']['main'], ConnectionFixtures::minimal());

    $config = OidcConfig::fromArray($values);

    expect($config->default)->toBe('main')
        ->and($config->connection()->algorithms)->toBe([SigningAlgorithm::RS256, SigningAlgorithm::PS256, SigningAlgorithm::ES256, SigningAlgorithm::EdDSA])
        ->and($config->http)->toEqual(new HttpConfig)
        ->and($config->cache)->toEqual(new CacheConfig);
});

it('keeps several named connections apart', function (): void {
    $config = OidcConfig::fromArray([
        'default' => 'workspace',
        'connections' => [
            'main' => ConnectionFixtures::minimal(),
            'workspace' => ConnectionFixtures::google(),
            'entra' => ConnectionFixtures::entraMultiTenant(),
        ],
    ]);

    expect($config->names())->toBe(['main', 'workspace', 'entra'])
        ->and($config->connection()->name)->toBe('workspace')
        ->and($config->connection('workspace')->tenant?->claim)->toBe('hd')
        ->and($config->connection('workspace')->tenant?->allows('example.com'))->toBeTrue()
        ->and($config->connection('workspace')->tenant?->allows('other.com'))->toBeFalse()
        ->and($config->connection('workspace')->authorizationParameters)->toBe(['access_type' => 'offline', 'prompt' => 'consent'])
        ->and($config->connection('workspace')->groups->source)->toBe(GroupsSource::None)
        ->and($config->connection('entra')->hasTenantTemplate())->toBeTrue()
        ->and($config->connection('entra')->discoveryUrl)->toBe('https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration')
        ->and($config->connection('main')->hasTenantTemplate())->toBeFalse();
});

it('defaults to the first connection when no default is set', function (): void {
    $config = OidcConfig::fromArray(['connections' => ['first' => ConnectionFixtures::minimal(), 'second' => ConnectionFixtures::google()]]);

    expect($config->default)->toBe('first');
});

it('names the known connections when asked for an unknown one', function (): void {
    $config = oidcConfig(ConnectionFixtures::minimal());

    expect(fn (): ConnectionConfig => $config->connection('missing'))
        ->toThrow(UnknownConnection::class, '[oidc_connection_unknown] There is no OIDC connection named "missing". Fix: Use one of main, or add it under connections in config/oidc.php.');
});

it('carries the error code and the fix on the exception', function (): void {
    $exception = refusal(ConnectionFixtures::minimal(['issuer' => null]));

    expect($exception->errorCode())->toBe(ErrorCode::ConfigInvalid)
        ->and($exception->key())->toBe('oidc.connections.main.issuer')
        ->and($exception->fix())->toBe('Set oidc.connections.main.issuer, usually from the environment.')
        ->and($exception->getMessage())->toBe('[oidc_config_invalid] oidc.connections.main.issuer must be a non-empty string. Fix: Set oidc.connections.main.issuer, usually from the environment.');
});

it('refuses an invalid connection value', function (array $overrides, string $key, string $problem): void {
    $exception = refusal(ConnectionFixtures::minimal($overrides));

    expect($exception->key())->toBe($key)
        ->and($exception->getMessage())->toContain($problem);
})->with([
    'http issuer' => [['issuer' => 'http://idp.example.test'], 'oidc.connections.main.issuer', 'must be an absolute https URL'],
    'relative issuer' => [['issuer' => '/realms/main'], 'oidc.connections.main.issuer', 'must be an absolute https URL'],
    'issuer with a query' => [['issuer' => 'https://idp.example.test/?tenant=a'], 'oidc.connections.main.issuer', 'must not have a query'],
    'issuer with a fragment' => [['issuer' => 'https://idp.example.test/#a'], 'oidc.connections.main.issuer', 'must not carry user info or a fragment'],
    'issuer with user info' => [['issuer' => 'https://user:pass@idp.example.test'], 'oidc.connections.main.issuer', 'must not carry user info or a fragment'],
    'two tenant templates' => [['issuer' => 'https://idp.example.test/{tenantid}/{tenantid}', 'tenant' => ['claim' => 'tid', 'allowed' => ['*']]], 'oidc.connections.main.issuer', 'uses {tenantid} more than once'],
    'template without tenant' => [['issuer' => 'https://idp.example.test/{tenantid}/v2.0', 'discovery_url' => 'https://idp.example.test/common/.well-known/openid-configuration'], 'oidc.connections.main.tenant', 'must pin the tid claim'],
    'template with hd tenant' => [['issuer' => 'https://idp.example.test/{tenantid}/v2.0', 'tenant' => ['claim' => 'hd', 'allowed' => ['a.com']]], 'oidc.connections.main.tenant', 'must pin the tid claim'],
    'template without discovery url' => [['issuer' => 'https://idp.example.test/{tenantid}/v2.0', 'tenant' => ['claim' => 'tid', 'allowed' => ['*']]], 'oidc.connections.main.discovery_url', 'is required when the issuer uses {tenantid}'],
    'http discovery url' => [['discovery_url' => 'http://idp.example.test/.well-known/openid-configuration'], 'oidc.connections.main.discovery_url', 'must be an absolute https URL'],
    'missing client id' => [['client_id' => ''], 'oidc.connections.main.client_id', 'must be a non-empty string'],
    'missing secret' => [['client_secret' => null], 'oidc.connections.main.client_secret', 'is required for client_auth client_secret_basic'],
    'unknown client auth' => [['client_auth' => 'tls_client_auth'], 'oidc.connections.main.client_auth', 'is not a supported client authentication method'],
    'relative redirect uri' => [['redirect_uri' => '/callback'], 'oidc.connections.main.redirect_uri', 'must be an absolute http or https URL'],
    'javascript redirect uri' => [['redirect_uri' => 'javascript://app.example.test/%0aalert(1)'], 'oidc.connections.main.redirect_uri', 'must be an absolute http or https URL'],
    'scopes without openid' => [['scopes' => ['profile']], 'oidc.connections.main.scopes', 'must contain openid'],
    'scope with a space' => [['scopes' => ['openid', 'a b']], 'oidc.connections.main.scopes.1', 'is not a valid scope'],
    'scope with a trailing newline' => [['scopes' => ['openid', "email\n"]], 'oidc.connections.main.scopes.1', 'is not a valid scope'],
    'scopes as a string' => [['scopes' => 'openid profile'], 'oidc.connections.main.scopes', 'must be a list of strings'],
    'algorithm none' => [['algorithms' => ['none']], 'oidc.connections.main.algorithms.0', 'names "none", which is not an accepted ID token algorithm'],
    'algorithm HS256' => [['algorithms' => ['RS256', 'HS256']], 'oidc.connections.main.algorithms.1', 'names "HS256"'],
    'no algorithms' => [['algorithms' => []], 'oidc.connections.main.algorithms', 'must list at least one algorithm'],
    'leeway too large' => [['leeway_seconds' => 301], 'oidc.connections.main.leeway_seconds', 'must be a whole number from 0 to 300'],
    'negative leeway' => [['leeway_seconds' => -1], 'oidc.connections.main.leeway_seconds', 'must be a whole number from 0 to 300'],
    'token age zero' => [['max_token_age_seconds' => 0], 'oidc.connections.main.max_token_age_seconds', 'must be a whole number from 1 to 86400'],
    'negative max age' => [['max_age' => -5], 'oidc.connections.main.max_age', 'must be a whole number from 0 to 31536000'],
    'tenant without tenants' => [['tenant' => ['claim' => 'hd', 'allowed' => []]], 'oidc.connections.main.tenant.allowed', 'must list at least one tenant'],
    'tenant mixing any' => [['tenant' => ['claim' => 'tid', 'allowed' => ['*', 'a']]], 'oidc.connections.main.tenant.allowed', 'mixes \'*\' with named tenants'],
    'tenant without claim' => [['tenant' => ['allowed' => ['a']]], 'oidc.connections.main.tenant.claim', 'must be a non-empty string'],
    'tenant as a string' => [['tenant' => 'hd'], 'oidc.connections.main.tenant', 'must be an array'],
    'unknown groups source' => [['groups' => ['source' => 'ldap']], 'oidc.connections.main.groups.source', 'is not a known groups source'],
    'reserved parameter' => [['authorization_parameters' => ['nonce' => 'fixed']], 'oidc.connections.main.authorization_parameters.nonce', 'is set by the package itself'],
    'reserved parameter in capitals' => [['authorization_parameters' => ['State' => 'fixed']], 'oidc.connections.main.authorization_parameters.State', 'is set by the package itself'],
    'parameters as a list' => [['authorization_parameters' => ['offline']], 'oidc.connections.main.authorization_parameters', 'must be a map of names to strings'],
    'http post logout uri' => [['post_logout_redirect_uri' => 'ftp://app.example.test/'], 'oidc.connections.main.post_logout_redirect_uri', 'must be an absolute http or https URL'],
]);

it('accepts a public client without a secret and drops a stray one', function (): void {
    $connection = oidcConfig(ConnectionFixtures::minimal(['client_auth' => 'none']))->connection();

    expect($connection->clientAuth)->toBe(ClientAuthMethod::None)
        ->and($connection->clientSecret)->toBeNull();
});

it('reads numbers given as strings, as env() returns them', function (): void {
    $connection = oidcConfig(ConnectionFixtures::minimal(['leeway_seconds' => '30', 'max_age' => '3600']))->connection();

    expect($connection->leewaySeconds)->toBe(30)
        ->and($connection->maxAge)->toBe(3600);
});

it('accepts any tenant only when asked for explicitly', function (): void {
    $tenant = oidcConfig(ConnectionFixtures::minimal(['tenant' => ['claim' => 'tid', 'allowed' => ['*']]]))->connection()->tenant;

    expect($tenant?->allowsAny())->toBeTrue()
        ->and($tenant?->allows('anything'))->toBeTrue();
});

it('removes duplicate scopes, algorithms and tenants', function (): void {
    $connection = oidcConfig(ConnectionFixtures::minimal([
        'scopes' => ['openid', 'email', 'openid'],
        'algorithms' => ['ES256', 'ES256', 'RS256'],
        'tenant' => ['claim' => 'hd', 'allowed' => ['a.com', 'a.com']],
    ]))->connection();

    expect($connection->scopes)->toBe(['openid', 'email'])
        ->and($connection->algorithms)->toBe([SigningAlgorithm::ES256, SigningAlgorithm::RS256])
        ->and($connection->tenant?->allowed)->toBe(['a.com']);
});

it('keeps the client secret out of dumps', function (): void {
    $connection = oidcConfig(ConnectionFixtures::minimal())->connection();

    expect(print_r($connection, true))->not->toContain('secret-1')->toContain('[redacted]');
});

it('refuses an invalid top-level value', function (mixed $values, string $key): void {
    expect(fn (): OidcConfig => OidcConfig::fromArray($values))
        ->toThrow(InvalidConfiguration::class, $key);
})->with([
    'not an array' => [null, 'oidc must be an array'],
    'no connections key' => [[], 'oidc.connections must be an array'],
    'no connections' => [['connections' => []], 'oidc.connections defines no connection'],
    'unnamed connection' => [['connections' => [ConnectionFixtures::minimal()]], 'oidc.connections.0 is not named'],
    'bad connection name' => [['connections' => ['main app' => ConnectionFixtures::minimal()]], 'oidc.connections.main app is not a valid connection name'],
    'connection name with a trailing newline' => [['connections' => ["main\n" => ConnectionFixtures::minimal()]], 'is not a valid connection name'],
    'transaction ttl too short' => [['connections' => ['main' => ConnectionFixtures::minimal()], 'flow' => ['transaction_ttl_seconds' => 5]], 'oidc.flow.transaction_ttl_seconds must be a whole number from 30 to 3600'],
    'no pending transactions' => [['connections' => ['main' => ConnectionFixtures::minimal()], 'flow' => ['max_pending_transactions' => 0]], 'oidc.flow.max_pending_transactions must be a whole number from 1 to 50'],
    'unknown default' => [['default' => 'other', 'connections' => ['main' => ConnectionFixtures::minimal()]], 'oidc.default names "other", which is not a configured connection'],
    'timeout too long' => [['connections' => ['main' => ConnectionFixtures::minimal()], 'http' => ['timeout_seconds' => 61]], 'oidc.http.timeout_seconds must be a number from 0.1 to 60'],
    'stale_if_error too long' => [['connections' => ['main' => ConnectionFixtures::minimal()], 'cache' => ['stale_if_error_seconds' => 604801]], 'oidc.cache.stale_if_error_seconds must be a whole number from 0 to 604800'],
    'jwks ttl range inverted' => [['connections' => ['main' => ConnectionFixtures::minimal()], 'cache' => ['jwks_min_ttl_seconds' => 900, 'jwks_max_ttl_seconds' => 600]], 'oidc.cache.jwks_min_ttl_seconds is larger than jwks_max_ttl_seconds'],
]);

it('reads the http, cache and flow settings', function (): void {
    $config = oidcConfig(ConnectionFixtures::minimal(), [
        'flow' => ['transaction_ttl_seconds' => '900', 'max_pending_transactions' => 3],
        'http' => ['timeout_seconds' => '2.5', 'connect_timeout_seconds' => 1, 'max_response_bytes' => 65536],
        'cache' => ['store' => 'redis', 'discovery_ttl_seconds' => 3600, 'jwks_default_ttl_seconds' => 600, 'jwks_min_ttl_seconds' => 60, 'jwks_max_ttl_seconds' => 7200, 'jwks_refetch_cooldown_seconds' => 30, 'stale_if_error_seconds' => '0'],
    ]);

    expect($config->http)->toEqual(new HttpConfig(2.5, 1.0, 65536))
        ->and($config->cache)->toEqual(new CacheConfig('redis', 3600, 600, 60, 7200, 30, 0))
        ->and($config->flow)->toEqual(new FlowConfig(900, 3))
        ->and(oidcConfig(ConnectionFixtures::minimal())->flow)->toEqual(new FlowConfig(600, 5));
});

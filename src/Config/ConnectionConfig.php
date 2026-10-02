<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;
use Cbox\Oidc\Tokens\SigningAlgorithm;
use SensitiveParameter;

/**
 * One connection of config/oidc.php: a client registered at one OpenID
 * provider, with the issuer it is pinned to.
 *
 * Build it from configuration with {@see self::fromConfig()}, which refuses
 * every invalid value with an {@see InvalidConfiguration} that names the key.
 */
readonly class ConnectionConfig
{
    /** The issuer placeholder Microsoft Entra uses in multi-tenant metadata. */
    public const string TENANT_TEMPLATE = '{tenantid}';

    /**
     * Authorization request parameters the package sets itself, which
     * authorization_parameters may not override.
     */
    public const array RESERVED_PARAMETERS = [
        'client_id', 'code_challenge', 'code_challenge_method', 'max_age', 'nonce',
        'redirect_uri', 'request', 'request_uri', 'response_mode', 'response_type', 'scope', 'state',
    ];

    /**
     * @param  non-empty-list<string>  $scopes
     * @param  non-empty-list<SigningAlgorithm>  $algorithms
     * @param  array<string, string>  $authorizationParameters
     */
    public function __construct(
        public string $name,
        public string $issuer,
        public string $discoveryUrl,
        public string $clientId,
        #[SensitiveParameter] public ?string $clientSecret,
        public ClientAuthMethod $clientAuth,
        public string $redirectUri,
        public array $scopes,
        public array $algorithms,
        public int $leewaySeconds,
        public int $maxTokenAgeSeconds,
        public ?int $maxAge,
        public ?TenantPolicy $tenant,
        public GroupsConfig $groups,
        public ?string $postLogoutRedirectUri,
        public array $authorizationParameters,
    ) {}

    public static function fromConfig(string $name, ConfigReader $config): self
    {
        $issuer = self::issuer($config);
        $tenant = $config->has('tenant') ? TenantPolicy::fromConfig($config->child('tenant')) : null;
        $templated = str_contains($issuer, self::TENANT_TEMPLATE);

        if ($templated && $tenant?->claim !== 'tid') {
            throw InvalidConfiguration::at($config->key('tenant'), 'must pin the tid claim when the issuer uses {tenantid}', sprintf('Set %s to [\'claim\' => \'tid\', \'allowed\' => [<tenant ids>]], or [\'*\'] to accept any tenant on purpose.', $config->key('tenant')));
        }

        if ($templated && ! $config->has('discovery_url')) {
            throw InvalidConfiguration::at($config->key('discovery_url'), 'is required when the issuer uses {tenantid}', sprintf('Set %s to the provider\'s multi-tenant metadata, such as https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration.', $config->key('discovery_url')));
        }

        $discoveryUrl = $config->has('discovery_url')
            ? $config->httpsUrl('discovery_url')
            : rtrim($issuer, '/').'/.well-known/openid-configuration';

        $clientAuth = ClientAuthMethod::tryFrom($config->string('client_auth', ClientAuthMethod::ClientSecretBasic->value));

        if ($clientAuth === null) {
            throw InvalidConfiguration::at($config->key('client_auth'), 'is not a supported client authentication method', sprintf('Set %s to client_secret_basic, client_secret_post or none.', $config->key('client_auth')));
        }

        $secret = $config->nullableString('client_secret');

        if ($clientAuth->needsSecret() && $secret === null) {
            throw InvalidConfiguration::at($config->key('client_secret'), sprintf('is required for client_auth %s', $clientAuth->value), sprintf('Set %s (usually OIDC_CLIENT_SECRET), or client_auth to none for a public client.', $config->key('client_secret')));
        }

        return new self(
            name: $name,
            issuer: $issuer,
            discoveryUrl: $discoveryUrl,
            clientId: $config->string('client_id'),
            clientSecret: $clientAuth->needsSecret() ? $secret : null,
            clientAuth: $clientAuth,
            redirectUri: $config->browserUrl('redirect_uri'),
            scopes: self::scopes($config),
            algorithms: self::algorithms($config),
            leewaySeconds: $config->int('leeway_seconds', 60, 0, 300),
            maxTokenAgeSeconds: $config->int('max_token_age_seconds', 600, 1, 86400),
            maxAge: $config->nullableInt('max_age', 0, 31536000),
            tenant: $tenant,
            groups: $config->has('groups') ? GroupsConfig::fromConfig($config->child('groups')) : new GroupsConfig,
            postLogoutRedirectUri: $config->has('post_logout_redirect_uri') ? $config->browserUrl('post_logout_redirect_uri') : null,
            authorizationParameters: self::authorizationParameters($config),
        );
    }

    /**
     * Whether the issuer is a template that the tenant claim fills in.
     */
    public function hasTenantTemplate(): bool
    {
        return str_contains($this->issuer, self::TENANT_TEMPLATE);
    }

    /**
     * Keeps the client secret out of dumps and logs.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'name' => $this->name,
            'issuer' => $this->issuer,
            'discoveryUrl' => $this->discoveryUrl,
            'clientId' => $this->clientId,
            'clientSecret' => $this->clientSecret === null ? null : '[redacted]',
            'clientAuth' => $this->clientAuth,
            'redirectUri' => $this->redirectUri,
            'scopes' => $this->scopes,
            'algorithms' => $this->algorithms,
            'leewaySeconds' => $this->leewaySeconds,
            'maxTokenAgeSeconds' => $this->maxTokenAgeSeconds,
            'maxAge' => $this->maxAge,
            'tenant' => $this->tenant,
            'groups' => $this->groups,
            'postLogoutRedirectUri' => $this->postLogoutRedirectUri,
            'authorizationParameters' => $this->authorizationParameters,
        ];
    }

    private static function issuer(ConfigReader $config): string
    {
        $issuer = $config->string('issuer');

        if (substr_count($issuer, self::TENANT_TEMPLATE) > 1) {
            throw InvalidConfiguration::at($config->key('issuer'), 'uses {tenantid} more than once', sprintf('Set %s to the issuer template exactly as the provider\'s metadata states it.', $config->key('issuer')));
        }

        $config->httpsUrl('issuer', str_replace(self::TENANT_TEMPLATE, 'tenant', $issuer));

        if (str_contains($issuer, '?')) {
            throw InvalidConfiguration::at($config->key('issuer'), 'must not have a query', sprintf('Set %s to the issuer exactly as the provider\'s discovery document states it.', $config->key('issuer')));
        }

        return $issuer;
    }

    /**
     * @return non-empty-list<string>
     */
    private static function scopes(ConfigReader $config): array
    {
        $scopes = $config->stringList('scopes', ['openid', 'profile', 'email']);

        foreach ($scopes as $index => $scope) {
            // RFC 6749 3.3 scope-token: %x21 / %x23-5B / %x5D-7E.
            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]+$/', $scope) !== 1) {
                throw InvalidConfiguration::at(sprintf('%s.%d', $config->key('scopes'), $index), 'is not a valid scope', sprintf('Use printable ASCII without spaces, quotes or backslashes in %s.', $config->key('scopes')));
            }
        }

        if (! in_array('openid', $scopes, true)) {
            throw InvalidConfiguration::at($config->key('scopes'), 'must contain openid', sprintf('Add \'openid\' to %s; without it the provider returns no ID token.', $config->key('scopes')));
        }

        return array_values(array_unique($scopes));
    }

    /**
     * @return non-empty-list<SigningAlgorithm>
     */
    private static function algorithms(ConfigReader $config): array
    {
        $names = $config->stringList('algorithms', SigningAlgorithm::names());
        $algorithms = [];

        foreach ($names as $index => $name) {
            $algorithm = SigningAlgorithm::tryFrom($name);

            if ($algorithm === null) {
                throw InvalidConfiguration::at(sprintf('%s.%d', $config->key('algorithms'), $index), sprintf('names "%s", which is not an accepted ID token algorithm', $name), sprintf('Use only %s; none and HS* are never accepted.', implode(', ', SigningAlgorithm::names())));
            }

            $algorithms[$algorithm->value] = $algorithm;
        }

        if ($algorithms === []) {
            throw InvalidConfiguration::at($config->key('algorithms'), 'must list at least one algorithm', sprintf('List the algorithms your provider signs with in %s, such as [\'RS256\'].', $config->key('algorithms')));
        }

        return array_values($algorithms);
    }

    /**
     * @return array<string, string>
     */
    private static function authorizationParameters(ConfigReader $config): array
    {
        $parameters = $config->stringMap('authorization_parameters');

        foreach (array_keys($parameters) as $parameter) {
            if (in_array(strtolower($parameter), self::RESERVED_PARAMETERS, true)) {
                throw InvalidConfiguration::at(sprintf('%s.%s', $config->key('authorization_parameters'), $parameter), 'is set by the package itself', sprintf('Remove %s from %s; use the connection\'s own setting for it where one exists.', $parameter, $config->key('authorization_parameters')));
            }
        }

        return $parameters;
    }
}

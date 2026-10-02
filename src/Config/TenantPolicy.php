<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;

/**
 * Pins the tenant of a connection: the ID token must carry $claim, and its
 * value must be one of $allowed. For Google Workspace that is hd with your
 * domains; for Microsoft Entra it is tid with tenant ids.
 *
 * ['*'] accepts any tenant, which a multi-tenant application chooses on
 * purpose; the claim must still be present.
 */
readonly class TenantPolicy
{
    public const string ANY = '*';

    /**
     * @param  non-empty-list<string>  $allowed
     */
    public function __construct(
        public string $claim,
        public array $allowed,
    ) {}

    public static function fromConfig(ConfigReader $config): self
    {
        $claim = $config->string('claim');
        $allowed = $config->stringList('allowed', []);

        if ($allowed === []) {
            throw InvalidConfiguration::at($config->key('allowed'), 'must list at least one tenant', sprintf('List the tenants you accept in %s, or [\'*\'] to accept any tenant on purpose.', $config->key('allowed')));
        }

        if (in_array(self::ANY, $allowed, true) && count($allowed) > 1) {
            throw InvalidConfiguration::at($config->key('allowed'), 'mixes \'*\' with named tenants', sprintf('Set %s to [\'*\'] alone, or list only named tenants.', $config->key('allowed')));
        }

        return new self($claim, array_values(array_unique($allowed)));
    }

    public function allowsAny(): bool
    {
        return $this->allowed === [self::ANY];
    }

    public function allows(string $tenant): bool
    {
        return $this->allowsAny() || in_array($tenant, $this->allowed, true);
    }
}

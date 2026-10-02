<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

use Cbox\Oidc\Exceptions\InvalidConfiguration;

/**
 * Where a connection reads group memberships from, and which claim holds them.
 */
readonly class GroupsConfig
{
    public function __construct(
        public GroupsSource $source = GroupsSource::IdToken,
        public string $claim = 'groups',
    ) {}

    public static function fromConfig(ConfigReader $config): self
    {
        $source = GroupsSource::tryFrom($config->string('source', GroupsSource::IdToken->value));

        if ($source === null) {
            throw InvalidConfiguration::at($config->key('source'), 'is not a known groups source', sprintf('Set %s to id_token, userinfo or none.', $config->key('source')));
        }

        return new self($source, $config->string('claim', 'groups'));
    }
}

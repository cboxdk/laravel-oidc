<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests;

use Cbox\Oidc\OidcServiceProvider;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Illuminate\Contracts\Config\Repository;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    /**
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [OidcServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $config = $app->make(Repository::class);
        $config->set('oidc.default', 'main');
        $config->set('oidc.connections', [
            'main' => ConnectionFixtures::minimal(),
            'workspace' => ConnectionFixtures::google(),
        ]);
    }
}

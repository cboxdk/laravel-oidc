<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests;

use Cbox\Oidc\OidcServiceProvider;
use Cbox\Oidc\Tests\Support\ConnectionFixtures;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Cbox\Ssrf\Testing\InteractsWithSsrf;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Http;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    use InteractsWithSsrf;

    protected function setUp(): void
    {
        parent::setUp();

        // DNS answers from a fixed table, and nothing reaches the network:
        // every provider call is answered by Http::fake() and still passes
        // the SSRF guard.
        $this->fakeSsrfDns([
            'idp.example.test' => [FakeProvider::ADDRESS],
            'accounts.google.com' => ['142.250.74.45'],
            'internal.example.test' => ['10.0.0.5'],
            'metadata.example.test' => ['169.254.169.254'],
        ]);
        Http::preventStrayRequests();
    }

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
        $config->set('cache.default', 'array');
        $config->set('session.driver', 'array');
        $config->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $config->set('oidc.default', 'main');
        $config->set('oidc.connections', [
            'main' => ConnectionFixtures::minimal(),
            'workspace' => ConnectionFixtures::google(),
        ]);
    }
}

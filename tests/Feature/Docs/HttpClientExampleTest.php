<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Tests\Support\FakeProvider;
use Psr\Log\AbstractLogger;
use Psr\Log\LoggerInterface;

it('runs the custom HTTP client of the extension-point docs', function (): void {
    $markdown = (string) file_get_contents(__DIR__.'/../../../docs/extension-points/http-client.md');
    expect(preg_match('/<!-- example: http-client -->\n```php\n(.*?)```/s', $markdown, $match))->toBe(1);

    $file = tempnam(sys_get_temp_dir(), 'oidc-example-');
    expect($file)->toBeString();
    file_put_contents((string) $file, $match[1]);

    try {
        require_once (string) $file;
    } finally {
        unlink((string) $file);
    }

    $log = new class extends AbstractLogger
    {
        /** @var list<array{string, array<array-key, mixed>}> */
        public array $records = [];

        public function log($level, string|Stringable $message, array $context = []): void
        {
            $this->records[] = [(string) $message, $context];
        }
    };

    app()->instance(LoggerInterface::class, $log);
    app()->singleton(HttpClient::class, 'LoggedHttpClient');
    new FakeProvider()->install();

    resolve(MetadataRepository::class)->for(resolve(OidcConfig::class)->connection());

    expect(resolve(HttpClient::class))->toBeInstanceOf('LoggedHttpClient')
        ->and($log->records)->toBe([['OIDC provider call', ['method' => 'GET', 'url' => FakeProvider::DISCOVERY_URL, 'status' => 200]]]);
});

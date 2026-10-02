<?php

declare(strict_types=1);

use Cbox\Oidc\Config\OidcConfig;

/**
 * Every ```php block of the docs that follows `<!-- example: config -->` is a
 * complete config/oidc.php file. This test loads each one and parses it, so a
 * documented configuration can never drift into one the package refuses.
 *
 * @return array<string, array{string, string}>
 */
function documentedConfigExamples(): array
{
    $examples = [];
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(__DIR__.'/../../../docs', FilesystemIterator::SKIP_DOTS));

    foreach ($files as $file) {
        if (! $file instanceof SplFileInfo || $file->getExtension() !== 'md') {
            continue;
        }

        $markdown = (string) file_get_contents($file->getPathname());
        preg_match_all('/<!-- example: config -->\n```php\n(.*?)```/s', $markdown, $matches);

        foreach ($matches[1] as $index => $code) {
            $examples[sprintf('%s #%d', $file->getFilename(), $index + 1)] = [$file->getPathname(), $code];
        }
    }

    ksort($examples);

    return $examples;
}

it('finds the documented configuration examples', function (): void {
    expect(array_keys(documentedConfigExamples()))->toBe(['reference.md #1', 'reference.md #2']);
});

it('parses every documented configuration example', function (string $path, string $code): void {
    $file = tempnam(sys_get_temp_dir(), 'oidc-example-');
    expect($file)->toBeString();
    file_put_contents((string) $file, $code);

    try {
        $config = OidcConfig::fromArray(require (string) $file);
    } finally {
        unlink((string) $file);
    }

    expect($config->names())->not->toBeEmpty()
        ->and($config->connection()->name)->toBe($config->default);
})->with(documentedConfigExamples());

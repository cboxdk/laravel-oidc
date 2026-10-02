<?php

declare(strict_types=1);

use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Tests\Support\DocExamples;

/**
 * Holds the documentation to the cboxdk docs standard and to the rule that
 * every code sample is backed by a test.
 */
function docsTestSources(): string
{
    $sources = '';
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(DocExamples::ROOT.'/tests', FilesystemIterator::SKIP_DOTS));

    foreach ($files as $file) {
        if ($file instanceof SplFileInfo && $file->getExtension() === 'php' && $file->getFilename() !== 'DocExamples.php') {
            $sources .= (string) file_get_contents($file->getPathname());
        }
    }

    return $sources;
}

/**
 * @return list<string>
 */
function docsPages(): array
{
    $pages = [];
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(DocExamples::ROOT.'/docs', FilesystemIterator::SKIP_DOTS));

    foreach ($files as $file) {
        if ($file instanceof SplFileInfo && $file->getExtension() === 'md') {
            $pages[] = $file->getPathname();
        }
    }

    sort($pages);

    return $pages;
}

/**
 * GitHub's anchor for a heading.
 */
function docsAnchor(string $heading): string
{
    return str_replace(' ', '-', (string) preg_replace('/[^a-z0-9 _-]/', '', strtolower(trim(str_replace('`', '', $heading)))));
}

it('ties every PHP sample to a test or a declaration', function (): void {
    $untied = array_map(
        static fn (array $block): string => sprintf('%s:%d', $block['file'], $block['line']),
        array_values(array_filter(DocExamples::blocks(), static fn (array $block): bool => $block['language'] === 'php' && $block['kind'] === null)),
    );

    expect($untied)->toBe([]);
});

it('runs every named example in some test', function (): void {
    $sources = docsTestSources();
    $names = array_unique(array_filter(array_map(
        static fn (array $block): ?string => $block['kind'] === 'example' && ! in_array($block['name'], ['config', 'config-fragment'], true) ? $block['name'] : null,
        DocExamples::blocks(),
    )));

    $unused = array_values(array_filter($names, static fn (string $name): bool => ! str_contains($sources, "'".$name."'") && ! str_contains($sources, 'example: '.$name.' ')));

    expect($unused)->toBe([]);
});

it('keeps the copies of a shared example equal', function (): void {
    foreach (array_unique(array_filter(array_column(DocExamples::blocks(), 'name'))) as $name) {
        if (! in_array($name, ['config', 'config-fragment'], true) && DocExamples::all($name) !== []) {
            expect(DocExamples::code($name))->toBeString();
        }
    }
});

it('quotes declared signatures exactly', function (): void {
    $signatures = array_filter(DocExamples::blocks(), static fn (array $block): bool => $block['kind'] === 'signature');

    expect($signatures)->not->toBeEmpty();

    foreach ($signatures as $block) {
        $class = (string) $block['name'];
        expect(interface_exists($class) || class_exists($class))->toBeTrue(sprintf('%s:%d names %s, which does not exist.', $block['file'], $block['line'], $class));

        $source = (string) preg_replace('/\s+/', ' ', (string) file_get_contents((string) new ReflectionClass($class)->getFileName()));

        foreach (array_filter(explode("\n", $block['code']), static fn (string $line): bool => str_contains($line, 'function ')) as $line) {
            expect($source)->toContain((string) preg_replace('/\s+/', ' ', trim($line)));
        }
    }
});

it('shows the real message of a coded error', function (): void {
    $message = DiscoveryFailed::issuerMismatch('main', 'https://login.example.com', 'https://login.example.com/')->getMessage();

    expect(DocExamples::code('error-message'))->toBe($message."\n");
});

it('lists every error code on the errors page', function (): void {
    $page = (string) file_get_contents(DocExamples::ROOT.'/docs/core-concepts/errors.md');

    foreach (ErrorCode::cases() as $code) {
        expect($page)->toContain('| `'.$code->value.'` |');
    }
});

it('gives every page its frontmatter and a matching title', function (string $page): void {
    $markdown = (string) file_get_contents($page);

    expect(preg_match('/\A---\ntitle: (.+)\ndescription: (.+)\nweight: (\d+)\n---\n\n# (.+)\n/', $markdown, $match))->toBe(1, $page.' lacks the frontmatter or the title')
        ->and($match[4])->toBe($match[1]);
})->with(fn (): array => array_combine(array_map(static fn (string $page): string => substr($page, strlen(DocExamples::ROOT) + 1), docsPages()), docsPages()));

it('gives every folder an index with the lowest weight, listing its pages', function (): void {
    $folders = [];

    foreach (docsPages() as $page) {
        preg_match('/^weight: (\d+)$/m', (string) file_get_contents($page), $weight);
        $folders[dirname($page)][basename($page)] = (int) ($weight[1] ?? 0);
    }

    unset($folders[DocExamples::ROOT.'/docs']);

    foreach ($folders as $folder => $pages) {
        expect($pages)->toHaveKey('_index.md');
        expect(min($pages))->toBe($pages['_index.md']);

        $index = (string) file_get_contents($folder.'/_index.md');

        foreach (array_keys($pages) as $page) {
            if ($page !== '_index.md') {
                expect($index)->toContain('('.$page.')');
            }
        }
    }
});

it('links only to files and headings that exist', function (): void {
    $broken = [];

    foreach ([DocExamples::ROOT.'/README.md', ...docsPages()] as $page) {
        $markdown = (string) preg_replace('/```.*?```/s', '', (string) file_get_contents($page));
        preg_match_all('/\]\(([^)\s]+)\)/', $markdown, $links);

        foreach ($links[1] as $link) {
            if (preg_match('/^[a-z]+:/', $link) === 1) {
                continue;
            }

            [$path, $fragment] = array_pad(explode('#', $link, 2), 2, null);
            $target = $path === '' ? $page : dirname($page).'/'.$path;

            if (! file_exists($target)) {
                $broken[] = sprintf('%s: %s', basename($page), $link);

                continue;
            }

            if ($fragment !== null && str_ends_with($target, '.md')) {
                preg_match_all('/^#{1,6} (.+)$/m', (string) preg_replace('/```.*?```/s', '', (string) file_get_contents($target)), $headings);

                if (! in_array($fragment, array_map(docsAnchor(...), $headings[1]), true)) {
                    $broken[] = sprintf('%s: %s', basename($page), $link);
                }
            }
        }
    }

    expect($broken)->toBe([]);
});

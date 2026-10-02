<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use FilesystemIterator;
use LogicException;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

/**
 * The code samples of the documentation (docs/ and README.md), so tests can
 * run them.
 *
 * A fenced block is tied to a test by the HTML comment on the line before it:
 *
 * - `<!-- example: <name> -->` is code a test loads and runs by its name
 *   (tests/Unit/Docs/DocsAuditTest.php checks that some test names it);
 *   `config` marks a complete config/oidc.php file, and `config-fragment`
 *   keys of one connection, which tests parse generically.
 * - `<!-- signature: <class> -->` is an excerpt of method signatures; each
 *   must be a method of that class or interface, as declared.
 */
final class DocExamples
{
    public const string ROOT = __DIR__.'/../..';

    /**
     * Every fenced block of every page.
     *
     * @return list<array{file: string, line: int, language: string, kind: string|null, name: string|null, code: string}>
     */
    public static function blocks(): array
    {
        $blocks = [];

        foreach (self::pages() as $file) {
            $lines = file($file, FILE_IGNORE_NEW_LINES);

            if ($lines === false) {
                throw new LogicException(sprintf('Cannot read %s.', $file));
            }

            $previous = '';

            for ($index = 0, $count = count($lines); $index < $count; $index++) {
                $line = $lines[$index];

                if (preg_match('/^```(\S*)$/', $line, $open) === 1 && $open[1] !== '') {
                    $start = $index;
                    $code = [];

                    while (++$index < $count && $lines[$index] !== '```') {
                        $code[] = $lines[$index];
                    }

                    $marker = preg_match('/^<!-- (example|signature): (\S+) -->$/', $previous, $match) === 1 ? $match : null;

                    $blocks[] = [
                        'file' => self::relative($file),
                        'line' => $start + 1,
                        'language' => $open[1],
                        'kind' => $marker[1] ?? null,
                        'name' => $marker[2] ?? null,
                        'code' => implode("\n", $code)."\n",
                    ];
                }

                if (trim($line) !== '') {
                    $previous = $line;
                }
            }
        }

        return $blocks;
    }

    /**
     * The code of the example named $name. An example may appear on several
     * pages, such as the setup in README.md and the quickstart; every copy
     * must then be the same, byte for byte.
     */
    public static function code(string $name): string
    {
        $copies = array_values(array_unique(self::all($name)));

        if (count($copies) !== 1) {
            throw new LogicException(count($copies) === 0
                ? sprintf('There is no example named "%s" in the docs.', $name)
                : sprintf('The copies of example "%s" differ: %s.', $name, implode(', ', array_keys(self::all($name)))));
        }

        return $copies[0];
    }

    /**
     * The examples of a kind shared by several blocks, such as config, keyed
     * by file and line.
     *
     * @return array<string, string>
     */
    public static function all(string $name): array
    {
        $examples = [];

        foreach (self::blocks() as $block) {
            if ($block['kind'] === 'example' && $block['name'] === $name) {
                $examples[sprintf('%s:%d', $block['file'], $block['line'])] = $block['code'];
            }
        }

        return $examples;
    }

    /**
     * Runs the example as a PHP file and returns what it returns. $variables
     * are in its scope, and $this is $bind when given (for snippets written
     * inside a service provider).
     *
     * @param  array<string, mixed>  $variables
     */
    public static function run(string $name, array $variables = [], ?object $bind = null): mixed
    {
        return self::runCode(self::code($name), $variables, $bind);
    }

    /**
     * @param  array<string, mixed>  $variables
     */
    public static function runCode(string $code, array $variables = [], ?object $bind = null): mixed
    {
        if (! str_starts_with(ltrim($code), '<?php')) {
            $code = "<?php\n\n".$code;
        }

        $file = tempnam(sys_get_temp_dir(), 'oidc-doc-');

        if ($file === false) {
            throw new LogicException('Cannot create a temporary file.');
        }

        file_put_contents($file, $code);

        $include = function (string $__file, array $__variables): mixed {
            extract($__variables);

            return require $__file;
        };

        try {
            return $bind === null
                ? $include($file, $variables)
                : \Closure::bind($include, $bind, $bind::class)($file, $variables);
        } finally {
            unlink($file);
        }
    }

    /** @var array<string, \Closure> */
    private static array $collected = [];

    private static int $runs = 0;

    /**
     * The Pest tests of an example that is a test file, by description,
     * without registering them with Pest: it() and test() collect them
     * instead. Bind each to the running test case and call it.
     *
     * @return array<string, \Closure>
     */
    public static function tests(string $name): array
    {
        $code = (string) preg_replace('/^<\?php\s*/', '', ltrim(self::code($name)));
        $namespace = sprintf('DocsExamples\\Run%d', ++self::$runs);
        $prelude = <<<PHP
            <?php

            namespace {$namespace};

            function it(string \$description, \\Closure \$test): void
            {
                \\Cbox\\Oidc\\Tests\\Support\\DocExamples::collect(\$description, \$test);
            }

            function test(string \$description, \\Closure \$test): void
            {
                it(\$description, \$test);
            }

            PHP;

        self::$collected = [];
        self::runCode($prelude.$code);
        $tests = self::$collected;
        self::$collected = [];

        return $tests;
    }

    /**
     * @internal called by the it() of {@see self::tests()}
     */
    public static function collect(string $description, \Closure $test): void
    {
        self::$collected[$description] = $test;
    }

    /**
     * @return list<string>
     */
    private static function pages(): array
    {
        $pages = [self::ROOT.'/README.md'];
        $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(self::ROOT.'/docs', FilesystemIterator::SKIP_DOTS));

        foreach ($files as $file) {
            if ($file instanceof SplFileInfo && $file->getExtension() === 'md') {
                $pages[] = $file->getPathname();
            }
        }

        sort($pages);

        return $pages;
    }

    private static function relative(string $file): string
    {
        return ltrim(substr((string) realpath($file), strlen((string) realpath(self::ROOT))), '/');
    }
}

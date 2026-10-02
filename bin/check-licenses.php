#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * License gate. Fails (exit 1) if any installed dependency is not offered under
 * at least one allowed license. Dual-licensed packages (SPDX "OR", e.g. nette's
 * "BSD-3-Clause OR GPL-3.0-only") pass as long as ONE choice is allowed — which
 * is exactly the choice we exercise. Run: `composer license-check`.
 */
const ALLOWED = [
    'MIT', 'MIT-0', 'ISC', '0BSD', 'Unlicense', 'WTFPL', 'CC0-1.0',
    'BSD-2-Clause', 'BSD-3-Clause', 'BSD-3-Clause-Clear', 'BSD-4-Clause',
    'Apache-2.0', 'Apache2', 'BSL-1.0', 'Zlib', 'PHP-3.01',
];

/**
 * Packages permitted despite a missing/odd license field, with justification.
 *
 * @return array<string, string>
 */
function licenseExceptions(): array
{
    return [
        // e.g. 'vendor/pkg' => 'public domain, confirmed upstream',
    ];
}

$lockPath = __DIR__.'/../composer.lock';

if (! is_file($lockPath)) {
    fwrite(STDERR, "composer.lock not found; run `composer install` first.\n");
    exit(2);
}

$lock = json_decode((string) file_get_contents($lockPath), true, 512, JSON_THROW_ON_ERROR);
$arguments = is_array($GLOBALS['argv'] ?? null) ? $GLOBALS['argv'] : [];

$includeDev = in_array('--dev', $arguments, true);
$packages = packagesInLock($lock, 'packages');

if ($includeDev) {
    $packages = [...$packages, ...packagesInLock($lock, 'packages-dev')];
}

$violations = [];
$checked = 0;

foreach ($packages as $package) {
    $name = is_string($package['name'] ?? null) ? $package['name'] : '?';
    $checked++;

    if (array_key_exists($name, licenseExceptions())) {
        continue;
    }

    $licenses = normalizeLicenses($package['license'] ?? []);

    if ($licenses === []) {
        $violations[$name] = '(no license declared)';

        continue;
    }

    $allowed = array_filter($licenses, static fn (string $l): bool => in_array($l, ALLOWED, true));

    if ($allowed === []) {
        $violations[$name] = implode(' OR ', $licenses);
    }
}

/**
 * The packages of a composer.lock section, each an array.
 *
 * @return list<array<array-key, mixed>>
 */
function packagesInLock(mixed $lock, string $section): array
{
    $packages = is_array($lock) && is_array($lock[$section] ?? null) ? $lock[$section] : [];

    return array_values(array_filter($packages, is_array(...)));
}

/**
 * Flatten a composer license field into individual SPDX identifiers, splitting
 * disjunctive/conjunctive expressions ("MIT OR GPL-2.0", "(MIT AND BSD)").
 *
 * @return list<string>
 */
function normalizeLicenses(mixed $license): array
{
    $items = is_array($license) ? array_filter($license, is_string(...)) : (is_string($license) ? [$license] : []);
    $out = [];

    foreach ($items as $item) {
        foreach (preg_split('/\s+(?:OR|AND)\s+/i', trim($item)) ?: [] as $part) {
            $part = trim($part, " \t()");
            if ($part !== '') {
                $out[] = $part;
            }
        }
    }

    return array_values(array_unique($out));
}

$scope = $includeDev ? 'production + dev' : 'production';

if ($violations !== []) {
    fwrite(STDERR, "License check FAILED ({$scope}): disallowed or missing licenses\n\n");
    foreach ($violations as $name => $license) {
        fwrite(STDERR, sprintf("  %-45s %s\n", $name, $license));
    }
    fwrite(STDERR, "\nAllowed: ".implode(', ', ALLOWED)."\n");
    fwrite(STDERR, "If a flagged package is genuinely fine, add it to licenseExceptions() with a reason.\n");
    exit(1);
}

echo "License check passed: all {$checked} {$scope} dependencies are permissively licensed.\n";
exit(0);

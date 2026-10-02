#!/usr/bin/env php
<?php

declare(strict_types=1);

/**
 * Generates a CycloneDX 1.5 SBOM (JSON) from composer.lock — self-contained, no
 * plugins or network. Output is deterministic (components sorted, serial number
 * derived from content) so a committed SBOM only changes when dependencies do.
 *
 *   composer sbom              # production dependencies -> sbom.json
 *   php bin/generate-sbom.php --dev --output=sbom-dev.json
 */
$root = dirname(__DIR__);
$lock = readJson($root.'/composer.lock');
$self = readJson($root.'/composer.json');
$selfName = is_string($self['name'] ?? null) ? $self['name'] : 'unknown/package';
$arguments = array_values(array_filter(is_array($GLOBALS['argv'] ?? null) ? $GLOBALS['argv'] : [], is_string(...)));

$includeDev = in_array('--dev', $arguments, true);
$output = $root.'/sbom.json';
foreach ($arguments as $arg) {
    if (str_starts_with($arg, '--output=')) {
        $output = substr($arg, strlen('--output='));
    }
}

$packages = lockedPackages($lock, 'packages');
if ($includeDev) {
    $packages = [...$packages, ...lockedPackages($lock, 'packages-dev')];
}

usort($packages, static fn (array $a, array $b): int => strcmp(stringOf($a['name'] ?? null), stringOf($b['name'] ?? null)));

$components = array_map(componentFor(...), $packages);

// Namespaced by this package's own name, so two cboxdk packages that happen to
// resolve the same dependency set still get distinct serial numbers.
$serial = 'urn:uuid:'.deterministicUuid($selfName, implode('|', array_map(static fn (array $component): string => $component['purl'], $components)));

$bom = [
    'bomFormat' => 'CycloneDX',
    'specVersion' => '1.5',
    'serialNumber' => $serial,
    'version' => 1,
    'metadata' => [
        'tools' => [[
            'vendor' => 'cboxdk',
            // Derived from the package rather than hard-coded, so a copy of this
            // script into a sibling package cannot keep claiming the wrong producer.
            'name' => basename($selfName).'-sbom',
            'version' => '1.0.0',
        ]],
        'component' => [
            'type' => 'library',
            'bom-ref' => $selfName,
            'name' => $selfName,
            'purl' => 'pkg:composer/'.$selfName,
        ],
    ],
    'components' => $components,
];

file_put_contents(
    $output,
    json_encode($bom, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)."\n",
);

printf("Wrote %s: %d components (%s).\n", $output, count($components), $includeDev ? 'production + dev' : 'production');

/**
 * The decoded JSON object of $path, or an empty array.
 *
 * @return array<array-key, mixed>
 */
function readJson(string $path): array
{
    $value = json_decode((string) file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);

    return is_array($value) ? $value : [];
}

/**
 * The packages of a composer.lock section, each an array.
 *
 * @param  array<array-key, mixed>  $lock
 * @return list<array<array-key, mixed>>
 */
function lockedPackages(array $lock, string $section): array
{
    $packages = is_array($lock[$section] ?? null) ? $lock[$section] : [];

    return array_values(array_filter($packages, is_array(...)));
}

function stringOf(mixed $value, string $default = ''): string
{
    return is_string($value) ? $value : $default;
}

/**
 * @param  array<array-key, mixed>  $package
 * @return array{type: string, bom-ref: string, group: string, name: string, version: string, purl: string, description?: string, licenses?: list<array<string, mixed>>, hashes?: list<array{alg: string, content: string}>}
 */
function componentFor(array $package): array
{
    $name = stringOf($package['name'] ?? null);
    $version = stringOf($package['version'] ?? null, '0.0.0');
    $purl = 'pkg:composer/'.$name.'@'.$version;
    [$group, $short] = array_pad(explode('/', $name, 2), 2, $name);

    $component = [
        'type' => 'library',
        'bom-ref' => $purl,
        'group' => $group,
        'name' => $short,
        'version' => $version,
        'purl' => $purl,
    ];

    if (isset($package['description']) && is_string($package['description'])) {
        $component['description'] = $package['description'];
    }

    $licenses = licenseEntries($package['license'] ?? []);
    if ($licenses !== []) {
        $component['licenses'] = $licenses;
    }

    $dist = is_array($package['dist'] ?? null) ? $package['dist'] : [];
    $shasum = $dist['shasum'] ?? '';
    if (is_string($shasum) && $shasum !== '') {
        $component['hashes'] = [['alg' => 'SHA-1', 'content' => $shasum]];
    }

    return $component;
}

/**
 * @return list<array<string, mixed>>
 */
function licenseEntries(mixed $license): array
{
    $items = array_values(array_filter(is_array($license) ? $license : [$license], is_string(...)));

    if ($items === []) {
        return [];
    }

    // A single declared license -> SPDX id; multiple -> an SPDX expression.
    if (count($items) === 1) {
        return [['license' => ['id' => $items[0]]]];
    }

    return [['expression' => '('.implode(' OR ', $items).')']];
}

function deterministicUuid(string $namespace, string $seed): string
{
    $hash = md5($namespace.':'.$seed);

    return sprintf(
        '%s-%s-4%s-%s-%s',
        substr($hash, 0, 8),
        substr($hash, 8, 4),
        substr($hash, 13, 3),
        dechex((hexdec($hash[16]) & 0x3) | 0x8).substr($hash, 17, 3),
        substr($hash, 20, 12),
    );
}

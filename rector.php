<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;
use RectorLaravel\Set\LaravelLevelSetList;
use RectorLaravel\Set\LaravelSetList;

return RectorConfig::configure()
    ->withPaths([
        __DIR__.'/bin',
        __DIR__.'/config',
        __DIR__.'/src',
        __DIR__.'/tests',
    ])
    // The PHP level follows composer.json's "php": "^8.4".
    ->withPhpSets()
    ->withPreparedSets(
        deadCode: true,
        codeQuality: true,
        typeDeclarations: true,
        earlyReturn: true,
    )
    // Laravel 12 is the lowest major the package supports, so no rule may
    // need anything newer.
    ->withSets([
        LaravelLevelSetList::UP_TO_LARAVEL_120,
        LaravelSetList::LARAVEL_CODE_QUALITY,
        LaravelSetList::LARAVEL_TYPE_DECLARATIONS,
    ]);

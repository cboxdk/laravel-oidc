<?php

declare(strict_types=1);

use Cbox\Oidc\Support\CacheControl;

it('reads max-age and clamps it to the bounds', function (?string $header, int $expected): void {
    expect(CacheControl::lifetime($header, 3600, 300, 86400))->toBe($expected);
})->with([
    'absent' => [null, 3600],
    'no max-age' => ['public, must-revalidate', 3600],
    'within bounds' => ['public, max-age=7200', 7200],
    'below the minimum' => ['max-age=10', 300],
    'above the maximum' => ['max-age=9999999', 86400],
    'zero' => ['max-age=0', 300],
    'no-store' => ['no-store', 300],
    'no-cache with max-age' => ['no-cache, max-age=7200', 300],
    'case and spaces' => ['Public, MAX-AGE = 600', 600],
    'quoted' => ['max-age="600"', 600],
    'not a number' => ['max-age=soon', 3600],
    'negative' => ['max-age=-5', 3600],
    'only s-maxage' => ['s-maxage=600', 3600],
]);

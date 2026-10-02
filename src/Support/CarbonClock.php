<?php

declare(strict_types=1);

namespace Cbox\Oidc\Support;

use Carbon\CarbonImmutable;
use Psr\Clock\ClockInterface;

/**
 * The default PSR-20 clock: Carbon's now, in UTC. It follows
 * Carbon::setTestNow(), so Laravel's $this->travel() and freezeTime() move
 * the package's clock in your tests together with the cache's.
 *
 * Bind your own Psr\Clock\ClockInterface to replace it; the package binds
 * this one only when the application has none.
 */
final readonly class CarbonClock implements ClockInterface
{
    public function now(): CarbonImmutable
    {
        return CarbonImmutable::now('UTC');
    }
}

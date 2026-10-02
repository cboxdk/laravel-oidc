<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use RuntimeException;
use Throwable;

/**
 * The base of every exception this package throws.
 *
 * Each one carries a stable {@see ErrorCode} and a fix: one sentence that says
 * what to change. The message repeats both, so a log line alone is enough.
 */
abstract class OidcException extends RuntimeException
{
    public function __construct(
        private readonly ErrorCode $errorCode,
        private readonly string $problem,
        private readonly string $fix,
        ?Throwable $previous = null,
    ) {
        parent::__construct(sprintf('[%s] %s Fix: %s', $errorCode->value, $problem, $fix), 0, $previous);
    }

    public function errorCode(): ErrorCode
    {
        return $this->errorCode;
    }

    /** What went wrong, without the code and the fix. */
    public function problem(): string
    {
        return $this->problem;
    }

    public function fix(): string
    {
        return $this->fix;
    }
}

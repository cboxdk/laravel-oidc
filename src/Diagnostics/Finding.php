<?php

declare(strict_types=1);

namespace Cbox\Oidc\Diagnostics;

use Cbox\Oidc\Exceptions\ErrorCode;
use Cbox\Oidc\Exceptions\OidcException;

/**
 * One check of a connection: what was checked, the verdict, what was found
 * and, when something is wrong, the fix and the error code a login would fail
 * with.
 */
final readonly class Finding
{
    public function __construct(
        public CheckStatus $status,
        public string $check,
        public string $message,
        public ?string $fix = null,
        public ?ErrorCode $code = null,
    ) {}

    public static function pass(string $check, string $message): self
    {
        return new self(CheckStatus::Pass, $check, $message);
    }

    public static function note(string $check, string $message): self
    {
        return new self(CheckStatus::Note, $check, $message);
    }

    public static function warn(string $check, string $message, string $fix): self
    {
        return new self(CheckStatus::Warn, $check, $message, $fix);
    }

    public static function fail(string $check, string $message, string $fix, ?ErrorCode $code = null): self
    {
        return new self(CheckStatus::Fail, $check, $message, $fix, $code);
    }

    public static function failed(string $check, OidcException $exception): self
    {
        return self::fail($check, $exception->problem(), $exception->fix(), $exception->errorCode());
    }

    /**
     * @return array{status: string, check: string, message: string, fix: string|null, code: string|null}
     */
    public function toArray(): array
    {
        return [
            'status' => $this->status->value,
            'check' => $this->check,
            'message' => $this->message,
            'fix' => $this->fix,
            'code' => $this->code?->value,
        ];
    }
}

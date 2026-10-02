<?php

declare(strict_types=1);

namespace Cbox\Oidc\Diagnostics;

/**
 * Everything {@see ConnectionDiagnostics} found for one connection, in the
 * order it checked. The checks stop at the first that fails and that the
 * next ones need (configuration, discovery).
 */
final readonly class Diagnosis
{
    /**
     * @param  list<Finding>  $findings
     */
    public function __construct(
        public string $connection,
        public array $findings,
    ) {}

    /** Whether no check failed. Warnings and notes do not count. */
    public function passed(): bool
    {
        return $this->count(CheckStatus::Fail) === 0;
    }

    public function count(CheckStatus $status): int
    {
        return count(array_filter($this->findings, static fn (Finding $finding): bool => $finding->status === $status));
    }

    /**
     * @return array{connection: string, passed: bool, findings: list<array{status: string, check: string, message: string, fix: string|null, code: string|null}>}
     */
    public function toArray(): array
    {
        return [
            'connection' => $this->connection,
            'passed' => $this->passed(),
            'findings' => array_map(static fn (Finding $finding): array => $finding->toArray(), $this->findings),
        ];
    }
}

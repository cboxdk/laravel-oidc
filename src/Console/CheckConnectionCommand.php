<?php

declare(strict_types=1);

namespace Cbox\Oidc\Console;

use Cbox\Oidc\Diagnostics\CheckStatus;
use Cbox\Oidc\Diagnostics\ConnectionDiagnostics;
use Cbox\Oidc\Diagnostics\Diagnosis;
use Cbox\Oidc\Diagnostics\Finding;
use Cbox\Oidc\Exceptions\OidcException;
use Illuminate\Console\Command;

/**
 * php artisan oidc:check [connection] [--all] [--json]
 *
 * Fetches the discovery document and the key set of a connection afresh and
 * prints what works and what does not, each problem with its fix. Exits 1
 * when a check fails.
 */
final class CheckConnectionCommand extends Command
{
    /** @var string */
    protected $signature = 'oidc:check
        {connection? : The connection to check; the default connection when left out}
        {--all : Check every configured connection}
        {--json : Print the result as JSON}';

    /** @var string */
    protected $description = 'Check an OIDC connection against its provider: configuration, discovery, signing keys and endpoints';

    public function handle(ConnectionDiagnostics $diagnostics): int
    {
        $connection = $this->argument('connection');
        $connection = is_string($connection) && $connection !== '' ? $connection : null;

        if ($this->option('all') === true) {
            try {
                $diagnoses = array_map($diagnostics->diagnose(...), $diagnostics->connections());
            } catch (OidcException $exception) {
                $diagnoses = [new Diagnosis('default', [Finding::failed('configuration', $exception)])];
            }
        } else {
            $diagnoses = [$diagnostics->diagnose($connection)];
        }

        if ($this->option('json') === true) {
            $this->line(json_encode(
                ['connections' => array_map(static fn (Diagnosis $diagnosis): array => $diagnosis->toArray(), $diagnoses)],
                JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
            ));
        } else {
            array_walk($diagnoses, $this->render(...));
        }

        foreach ($diagnoses as $diagnosis) {
            if (! $diagnosis->passed()) {
                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }

    private function render(Diagnosis $diagnosis): void
    {
        $this->newLine();
        $this->line(sprintf('  <options=bold>Connection %s</>', $diagnosis->connection));
        $this->newLine();

        foreach ($diagnosis->findings as $finding) {
            [$label, $color] = match ($finding->status) {
                CheckStatus::Pass => ['PASS', 'green'],
                CheckStatus::Note => ['NOTE', 'blue'],
                CheckStatus::Warn => ['WARN', 'yellow'],
                CheckStatus::Fail => ['FAIL', 'red'],
            };

            $this->line(sprintf('  <fg=%s;options=bold>%s</>  %-14s %s', $color, $label, $finding->check, $this->escape($finding->message)));

            if ($finding->fix !== null) {
                $this->line(sprintf('  %20s<fg=gray>%sFix: %s</>', '', $finding->code === null ? '' : '['.$finding->code->value.'] ', $this->escape($finding->fix)));
            }
        }

        $failures = $diagnosis->count(CheckStatus::Fail);
        $warnings = $diagnosis->count(CheckStatus::Warn);

        $this->newLine();
        $this->line($failures === 0
            ? sprintf('  <fg=green>Connection %s can sign people in%s.</>', $diagnosis->connection, $warnings === 0 ? '' : sprintf(', with %d warning(s)', $warnings))
            : sprintf('  <fg=red>Connection %s cannot sign people in: %d check(s) failed.</>', $diagnosis->connection, $failures));
    }

    /** Provider values may hold console markup; print them as text. */
    private function escape(string $text): string
    {
        return str_replace(['<', '>'], ['\\<', '\\>'], $text);
    }
}

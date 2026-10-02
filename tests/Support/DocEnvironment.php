<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tests\Support;

use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\GuardPolicy;
use LogicException;

/**
 * Runs a documented .env block the way an application reads it: its lines go
 * into the environment, and the published config/oidc.php (and the SSRF
 * guard's enforce switch) are read again under them. Call restore() after
 * the test.
 */
final class DocEnvironment
{
    /** @var list<string> */
    private static array $keys = [];

    /**
     * @return array<string, string>
     */
    public static function parse(string $dotenv): array
    {
        $values = [];

        foreach (explode("\n", $dotenv) as $line) {
            $line = trim($line);

            if ($line === '' || str_starts_with($line, '#')) {
                continue;
            }

            if (preg_match('/^([A-Z][A-Z0-9_]*)=(.*)$/D', $line, $match) !== 1) {
                throw new LogicException(sprintf('"%s" is not a KEY=value line.', $line));
            }

            $values[$match[1]] = trim($match[2], '"');
        }

        return $values;
    }

    /**
     * Puts the lines of $dotenv into the environment (APP_ENV excepted: the
     * tests run as testing, which the package treats as local) and reads the
     * published configuration again.
     */
    public static function use(string $dotenv): void
    {
        foreach (self::parse($dotenv) as $key => $value) {
            if ($key === 'APP_ENV') {
                continue;
            }

            putenv($key.'='.$value);
            $_SERVER[$key] = $value;
            self::$keys[] = $key;
        }

        config([
            'oidc' => require DocExamples::ROOT.'/config/oidc.php',
            'ssrf.enforce' => env('SSRF_ENFORCE', true),
        ]);

        Refusals::forgetServices();
        app()->forgetInstance(GuardPolicy::class);
        app()->forgetInstance(UrlGuard::class);
    }

    public static function restore(): void
    {
        foreach (self::$keys as $key) {
            putenv($key);
            unset($_SERVER[$key]);
        }

        self::$keys = [];
    }
}

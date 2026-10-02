<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;
use Throwable;

/**
 * The provider could not be reached, timed out, or answered with a temporary
 * failure. Unlike {@see InvalidProviderResponse}, retrying later may succeed,
 * so a login form can say "try again" rather than "denied".
 */
class ProviderUnavailable extends OidcException
{
    public static function unreachable(string $url, Throwable $previous): self
    {
        return new self(
            ErrorCode::ProviderUnavailable,
            sprintf('The provider at %s could not be reached: %s', Url::origin($url), $previous->getMessage()),
            'Check that the provider is up and reachable from this server, and that oidc.http.timeout_seconds is long enough. Retry later.',
            $previous,
        );
    }

    public static function status(string $url, int $status): self
    {
        return new self(
            ErrorCode::ProviderUnavailable,
            sprintf('The provider answered %s with HTTP %d, a temporary failure.', Url::withoutQuery($url), $status),
            'Retry later. If it persists, check the provider\'s status page.',
        );
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;

/**
 * The discovery document of a connection cannot be used: it names another
 * issuer than the connection pins, or lacks or misstates a value the protocol
 * needs. The connection stays unusable until the configuration or the
 * provider is fixed.
 */
class DiscoveryFailed extends OidcException
{
    public static function issuerMismatch(string $connection, string $expected, string $actual): self
    {
        return new self(
            ErrorCode::DiscoveryIssuerMismatch,
            sprintf('The discovery document of connection "%s" names the issuer "%s", but the connection pins "%s". They must be equal, character for character (RFC 8414 3.3).', $connection, self::shorten($actual), $expected),
            sprintf('If "%s" is the provider you mean, set oidc.connections.%s.issuer to it exactly, trailing slash included. Otherwise check discovery_url.', self::shorten($actual), $connection),
        );
    }

    public static function invalid(string $connection, string $url, string $problem, string $fix): self
    {
        return new self(
            ErrorCode::DiscoveryInvalid,
            sprintf('The discovery document of connection "%s" at %s %s.', $connection, Url::withoutQuery($url), $problem),
            $fix,
        );
    }

    private static function shorten(string $value): string
    {
        return strlen($value) > 200 ? substr($value, 0, 200).'...' : $value;
    }
}

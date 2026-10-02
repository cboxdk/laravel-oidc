<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;
use Throwable;

/**
 * The provider answered, but not with what the protocol requires. Retrying
 * does not help; the URL or the provider's setup needs a look.
 */
class InvalidProviderResponse extends OidcException
{
    public static function status(string $url, int $status): self
    {
        return new self(
            ErrorCode::ProviderResponseInvalid,
            sprintf('The provider answered %s with HTTP %d.', Url::withoutQuery($url), $status),
            $status >= 300 && $status < 400
                ? 'Use the final URL: provider calls never follow redirects, so a redirecting URL cannot be used.'
                : 'Check the URL; for discovery, set discovery_url to the provider\'s .well-known/openid-configuration.',
        );
    }

    public static function tooLarge(string $url, int $limit): self
    {
        return new self(
            ErrorCode::ProviderResponseInvalid,
            sprintf('The response from %s is larger than %d bytes.', Url::withoutQuery($url), $limit),
            'Raise oidc.http.max_response_bytes if the provider legitimately serves a document this large.',
        );
    }

    public static function encoded(string $url, string $encoding): self
    {
        return new self(
            ErrorCode::ProviderResponseInvalid,
            sprintf('The response from %s is compressed (Content-Encoding %s), although the request asked for identity encoding.', Url::withoutQuery($url), substr((string) preg_replace('/[^\x21-\x7E ]/', '?', $encoding), 0, 64)),
            'Configure the provider, or the proxy or CDN in front of it, to honour Accept-Encoding: identity. Compressed bodies are refused because they can expand past oidc.http.max_response_bytes.',
        );
    }

    public static function malformed(string $url, string $what, string $problem, ?Throwable $previous = null): self
    {
        return new self(
            ErrorCode::ProviderResponseInvalid,
            sprintf('The %s from %s is not valid: %s.', $what, Url::withoutQuery($url), $problem),
            'Check that the URL serves the provider\'s JSON document and not, for example, an HTML login or error page.',
            $previous,
        );
    }
}

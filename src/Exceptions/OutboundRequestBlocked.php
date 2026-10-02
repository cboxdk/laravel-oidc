<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;
use Throwable;

/**
 * The SSRF guard (cboxdk/laravel-ssrf) refused a URL the package was about to
 * call: it is not https, or it resolves to a private, loopback or metadata
 * address. Every call to a provider goes through the guard, including the
 * URLs a discovery document names.
 */
class OutboundRequestBlocked extends OidcException
{
    public static function url(string $url, Throwable $previous): self
    {
        return new self(
            ErrorCode::HttpBlocked,
            sprintf('The SSRF guard refused a call to %s: %s', Url::origin($url), $previous->getMessage()),
            'Point the connection at the provider\'s public https address. For a provider on a private network, change config/ssrf.php on purpose; a network egress allow-list is the complete control.',
            $previous,
        );
    }
}

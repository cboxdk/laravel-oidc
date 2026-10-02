<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Support\Url;

/**
 * The provider's key set (the document at jwks_uri) is not a usable JSON Web
 * Key Set (RFC 7517 5).
 */
class KeySetInvalid extends OidcException
{
    public static function because(string $connection, string $url, string $problem): self
    {
        return new self(
            ErrorCode::KeySetInvalid,
            sprintf('The key set of connection "%s" at %s %s.', $connection, Url::withoutQuery($url), $problem),
            'Check that jwks_uri in the provider\'s discovery document serves its public signing keys as {"keys": [...]}.',
        );
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

/**
 * What a private_key_jwt client assertion names as its audience (aud).
 */
enum AssertionAudience: string
{
    /**
     * The provider's token endpoint URL, as OpenID Connect Core 9 says and
     * Microsoft Entra and Okta require. The default.
     */
    case TokenEndpoint = 'token_endpoint';

    /**
     * The provider's issuer identifier, which the 2025 update of RFC 7523
     * recommends because it cannot be mixed up between providers. Use it
     * where the provider accepts it.
     */
    case Issuer = 'issuer';
}

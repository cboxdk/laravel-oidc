<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

/**
 * What a private_key_jwt client assertion names as its audience (aud).
 *
 * Either way, an assertion is only good where it was sent: a provider that
 * advertises another party's URL as one of its endpoints receives an
 * assertion for its own URL or its own issuer, never one another provider
 * accepts (the audience injection that the 2025 update of RFC 7523 closes).
 */
enum AssertionAudience: string
{
    /**
     * The URL of the endpoint the assertion is sent to: the token endpoint
     * for a token request, as OpenID Connect Core 9 says and Microsoft Entra
     * and Okta require, and the revocation endpoint for a revocation. The
     * default.
     */
    case Endpoint = 'endpoint';

    /**
     * The provider's issuer identifier, which the 2025 update of RFC 7523
     * requires. Use it where the provider accepts it.
     */
    case Issuer = 'issuer';
}

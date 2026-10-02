<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * Every error the package raises carries one of these codes. A code is stable:
 * it is never renamed, so you can match on it in logs and alerts.
 */
enum ErrorCode: string
{
    /** A value in config/oidc.php is missing or invalid. */
    case ConfigInvalid = 'oidc_config_invalid';

    /** Code asked for a connection that config/oidc.php does not define. */
    case ConnectionUnknown = 'oidc_connection_unknown';

    /** The SSRF guard refused a URL the package was about to call. */
    case HttpBlocked = 'oidc_http_blocked';

    /**
     * The provider could not be reached, timed out, or answered with a
     * temporary failure (5xx, 408, 429). Retrying later may succeed.
     */
    case ProviderUnavailable = 'oidc_provider_unavailable';

    /**
     * The provider answered, but not with what the protocol requires: an
     * unexpected status, a body over the size limit, or malformed JSON.
     */
    case ProviderResponseInvalid = 'oidc_provider_response_invalid';

    /** The discovery document names another issuer than the connection pins (RFC 8414 3.3). */
    case DiscoveryIssuerMismatch = 'oidc_discovery_issuer_mismatch';

    /** The discovery document lacks a required value, or one is unusable. */
    case DiscoveryInvalid = 'oidc_discovery_invalid';

    /** The provider's key set (JWKS) is not a usable JSON Web Key Set. */
    case KeySetInvalid = 'oidc_jwks_invalid';

    /** No key of the provider's key set can verify the token. */
    case SigningKeyNotFound = 'oidc_signing_key_not_found';

    /** The key the token names exists but may not verify it (type, curve, size, use or alg). */
    case SigningKeyUnsuitable = 'oidc_signing_key_unsuitable';
}

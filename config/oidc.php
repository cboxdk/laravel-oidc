<?php

declare(strict_types=1);

/*
 * Cbox OIDC configuration.
 *
 * Every value is parsed into typed objects (Cbox\Oidc\Config\OidcConfig) the
 * first time the package needs it. A wrong value fails with an
 * InvalidConfiguration exception that names the key and how to fix it, so a
 * typo never turns into a silently weaker login.
 */

return [

    /*
     * The connection used when code does not name one.
     */
    'default' => env('OIDC_CONNECTION', 'main'),

    /*
     * One entry per OpenID provider (or per tenant of one). The key is the
     * connection name your code and routes refer to.
     */
    'connections' => [

        'main' => [
            // The issuer exactly as the provider's discovery document states
            // it. https only, no query and no fragment. For Microsoft Entra
            // multi-tenant apps, use the {tenantid} template together with a
            // tenant policy on the tid claim (see "tenant" below).
            'issuer' => env('OIDC_ISSUER'),

            // Null means issuer + /.well-known/openid-configuration.
            'discovery_url' => env('OIDC_DISCOVERY_URL'),

            'client_id' => env('OIDC_CLIENT_ID'),
            'client_secret' => env('OIDC_CLIENT_SECRET'),

            // client_secret_basic, client_secret_post, private_key_jwt (a JWT
            // signed with your private key, see client_assertion), or none for
            // a public client (PKCE only, no secret).
            'client_auth' => 'client_secret_basic',

            // Only read when client_auth is private_key_jwt.
            'client_assertion' => [
                // The private key: PEM text in key, or a PEM file in key_path.
                'key' => env('OIDC_CLIENT_KEY'),
                'key_path' => env('OIDC_CLIENT_KEY_PATH'),
                'passphrase' => env('OIDC_CLIENT_KEY_PASSPHRASE'),
                // Sent as kid, so the provider finds the public key.
                'key_id' => env('OIDC_CLIENT_KEY_ID'),
                // RS256, PS256, ES256 or EdDSA (and the 384/512 variants).
                'algorithm' => 'RS256',
                // token_endpoint (OpenID Connect Core; Entra, Okta) or issuer.
                'audience' => 'token_endpoint',
                // Extra header members, such as Entra's x5t#S256 thumbprint.
                'headers' => [],
                'lifetime_seconds' => 60,
            ],

            // Where the provider sends the browser back after login. Register
            // exactly this URL at the provider.
            'redirect_uri' => env('OIDC_REDIRECT_URI'),

            // Must contain openid. Add offline_access where the provider
            // honours it to get a refresh token.
            'scopes' => ['openid', 'profile', 'email'],

            // ID token signature algorithms this connection accepts. none and
            // the HS* family are never accepted.
            'algorithms' => ['RS256', 'PS256', 'ES256', 'EdDSA'],

            // Allowed clock skew for exp, nbf, iat and auth_time (0 to 300).
            'leeway_seconds' => 60,

            // Refuse an ID token issued longer ago than this.
            'max_token_age_seconds' => 600,

            // Sent as max_age; when set, auth_time becomes required. Null
            // leaves it out.
            'max_age' => null,

            // Pin the tenant claim. Google Workspace: claim hd with your
            // domains. Microsoft Entra: claim tid with the tenant ids you
            // accept, or ['*'] to accept any tenant on purpose. Null when the
            // provider has no tenants.
            'tenant' => null,

            // Where group memberships come from: id_token, userinfo or none,
            // and the claim that holds them.
            'groups' => [
                'source' => 'id_token',
                'claim' => 'groups',
            ],

            // Where the provider returns the browser after RP-initiated
            // logout. Null leaves post_logout_redirect_uri out.
            'post_logout_redirect_uri' => env('OIDC_POST_LOGOUT_REDIRECT_URI'),

            // Extra authorization request parameters, such as Google's
            // access_type => offline. Protocol parameters the package sets
            // itself (state, nonce, PKCE, scope and so on) are refused here.
            'authorization_parameters' => [],
        ],

    ],

    /*
     * Outbound HTTP to the providers (discovery, keys, token, userinfo,
     * revocation). Every call goes through cboxdk/laravel-ssrf and never
     * follows redirects.
     */
    'http' => [
        'timeout_seconds' => 5,
        'connect_timeout_seconds' => 2,
        // Largest response body accepted from a provider.
        'max_response_bytes' => 262144,
    ],

    /*
     * The authorization flow: how long a started login may wait for its
     * callback, and how many may wait at once per session (one per tab).
     */
    'flow' => [
        'transaction_ttl_seconds' => 600,
        'max_pending_transactions' => 5,
    ],

    /*
     * Caching of discovery documents and key sets.
     */
    'cache' => [
        // Cache store name; null uses the application's default store.
        'store' => null,
        'discovery_ttl_seconds' => 86400,
        // The JWKS lifetime follows the provider's Cache-Control max-age,
        // clamped to [min, max]; default when the provider sends none.
        'jwks_default_ttl_seconds' => 3600,
        'jwks_min_ttl_seconds' => 300,
        'jwks_max_ttl_seconds' => 86400,
        // An unknown kid triggers at most one key refetch per this window.
        'jwks_refetch_cooldown_seconds' => 60,
        // When a document is stale and the provider is unavailable (network
        // error, timeout, 5xx), keep using the stale copy this much longer.
        // 0 fails at once. A wrong document is never replaced by a stale one.
        'stale_if_error_seconds' => 86400,
    ],

];

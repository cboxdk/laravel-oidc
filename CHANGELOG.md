# Changelog

All notable changes to `cboxdk/laravel-oidc` are documented here. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Typed, multi-connection configuration.** `config/oidc.php` defines any
  number of named connections and a default. On first use the package parses
  it into `OidcConfig`, `ConnectionConfig` and their parts, and refuses every
  invalid value with `InvalidConfiguration`: a stable code
  (`oidc_config_invalid`), the full key and a one-line fix. The issuer must be
  https without a query or fragment, `scopes` must contain `openid`, `none` and
  the `HS*` algorithms cannot be configured, a `{tenantid}` issuer needs a
  tenant policy on `tid`, and authorization parameters the package sets itself
  cannot be overridden.
- **Service provider** `OidcServiceProvider`, auto-discovered, which merges the
  defaults, binds `OidcConfig` as a lazy singleton and publishes the config
  under the `oidc-config` tag.
- **Exceptions with codes and fixes.** Every exception extends `OidcException`
  and carries an `ErrorCode`, a `problem()` and a `fix()`.
- **An injectable HTTP client behind the SSRF guard.** Every call to a provider
  goes through `Contracts\HttpClient`. The default, `LaravelHttpClient`, uses
  Laravel's HTTP client (so `Http::fake()` works) with the
  `cboxdk/laravel-ssrf` guard in its handler stack: https only, no redirects,
  the configured timeouts and a body size limit. Failures are
  `OutboundRequestBlocked` (`oidc_http_blocked`), `ProviderUnavailable`
  (`oidc_provider_unavailable`) and `InvalidProviderResponse`
  (`oidc_provider_response_invalid`).
- **Discovery.** `MetadataRepository` fetches each connection's discovery
  document and `ProviderMetadata` checks it: an exact issuer match (RFC 8414
  3.3), https endpoints, a common ID token algorithm, and, where listed, the
  code response type, PKCE S256 and the connection's client authentication.
  Failures are `DiscoveryFailed` (`oidc_discovery_issuer_mismatch`,
  `oidc_discovery_invalid`). JSON with duplicate keys is refused.
- **Signing keys.** `KeySetRepository` fetches the provider's key set and reads
  it with web-token; `SigningKeys::find()` picks the one key that may verify a
  token from its `alg` and `kid`, checking type, curve, use, alg, RSA size and
  exponent and EC points with web-token's analyzers. An unknown `kid`
  refetches the key set once, with a cooldown shared across processes.
  Failures are `KeySetInvalid` (`oidc_jwks_invalid`), `SigningKeyNotFound` and
  `SigningKeyUnsuitable`.
- **Caching with stale-if-error.** Discovery documents and key sets are cached
  in the configured store, key sets for the provider's `max-age` within the
  configured bounds. The new `oidc.cache.stale_if_error_seconds` (one day by
  default) keeps a stale copy in use while the provider is unavailable.
- **The authorization code flow.** `AuthorizationFlow::start()` (or
  `redirect()`) makes a fresh 256-bit state and nonce and a PKCE S256
  verifier, keeps them in a `TransactionStore`, and returns an
  `AuthorizationRequest` that Laravel answers as a redirect. Per-login
  `AuthorizationOptions` add `prompt`, `max_age`, `login_hint`, scopes,
  `acr_values` and other parameters, each checked where it is written
  (`oidc_authorization_options_invalid`). The authorization URL keeps the
  endpoint's own query and passes the SSRF guard's redirect check.
- **The callback.** `AuthorizationFlow::callback()` checks, in order, the
  state (bound to this session and connection, used once, within
  `oidc.flow.transaction_ttl_seconds`), the RFC 9207 `iss` parameter (Entra's
  `{tenantid}` template included), an error answer (`AuthorizationDenied`, with
  the error code only and `interactionRequired()` for silent logins) and the
  code, then exchanges the code. Failures are `CallbackRejected`
  (`oidc_state_mismatch`, `oidc_transaction_expired`,
  `oidc_callback_issuer_mismatch`, `oidc_callback_invalid`). It returns a
  `CallbackResult` with the `TokenSet`; the ID token is not verified yet.
- **The token endpoint.** `TokenEndpoint` sends grants with the connection's
  client authentication: `client_secret_basic` (form-encoded first, as RFC
  6749 2.3.1 says), `client_secret_post`, the new `private_key_jwt` (RFC 7523,
  signed with web-token from a PEM key under `client_assertion`, RSA, EC or
  Ed25519) or none. A token response must be a JSON object with an
  `access_token`, `token_type` Bearer and, for a code, an `id_token`; an OAuth
  error is `TokenRequestRejected` (`oidc_token_request_rejected`) with its
  error code only.
- **A session transaction store.** `SessionTransactionStore`, the default
  `TransactionStore`, keeps started logins in the Laravel session under the
  SHA-256 of their state, at most `oidc.flow.max_pending_transactions` (5) at
  once. Bind your own to keep them elsewhere.
- **A PSR-20 clock.** The package reads time from `Psr\Clock\ClockInterface`;
  the default `CarbonClock` follows Carbon, so Laravel's time travel moves it in
  tests. An application's own clock or HTTP client binding wins.

### Fixed

- **Anchored patterns accepted a trailing newline.** A scope, connection name
  or number in `config/oidc.php` ending in a newline passed its check, because
  `$` in a PHP pattern also matches before a final newline. Every anchored
  pattern now uses the `D` modifier.

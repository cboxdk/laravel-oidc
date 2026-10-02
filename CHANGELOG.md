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
  `CallbackResult` with the `TokenSet` and the verified claims of the ID
  token.
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

- **ID token verification.** `IdTokenVerifier` verifies an ID token in a
  fixed order: compact JWS only (at most 16 KiB, canonical base64url, no JWE,
  no `crit` or `b64`, no `typ` of another kind of token), `alg` on the
  connection's allow-list and the provider's, the key by `kid`, the signature
  through web-token with a one-algorithm manager, then `iss`, `aud` and `azp`,
  `exp`, `nbf` and `iat` (web-token's checkers with the PSR-20 clock and the
  connection's leeway), the token's age, `nonce` in constant time, `sub`,
  `auth_time` against `max_age`, and `at_hash` with the algorithm's hash
  (SHA-512 for EdDSA). `callback()` now verifies the ID token against the
  login's nonce and `max_age`, the access token and the callback's `iss`.
  Failures are `TokenRejected`, with a code per rule and `claim()` naming the
  claim.
- **Tenant pinning.** A connection's tenant policy is enforced on the ID
  token: Google Workspace's `hd` and Microsoft Entra's `tid`, compared without
  case, other claims exactly. For an Entra `{tenantid}` issuer, `tid` must be a
  GUID, the issuer is checked with it filled in, and the signing key's own
  `issuer` must match. Failures are `TenantRejected` (`oidc_tenant_claim_missing`,
  `oidc_tenant_not_allowed`), which extends `TokenRejected`.
- **Verified claims.** `VerifiedClaims` gives the issuer, subject, audience,
  `azp`, `iat`, `exp` and `auth_time` as dates, `amr` (each method once),
  `acr`, `sid`, the tenant, the groups of the configured claim (null with
  `groupsOverage` for Entra's group overage), `email()`, `emailVerified()`,
  `name()`, and every claim through `claim()`, `string()`, `has()` and
  `all()`. `CallbackResult::$claims` carries them.
- **Key validity.** A key of the provider's key set marked `revoked`, or
  outside its `exp` and `nbf` members (OpenID Federation key sets), no longer
  fits a token.
- **Refresh tokens.** `TokenRefresher::refresh($claims, $refreshToken)` uses
  the refresh token at the token endpoint of the login's connection and returns
  a `RefreshResult`: the new tokens, the refresh token to keep (the rotated one,
  or the old one) and the verified claims of the new ID token. That ID token
  passes every ID token rule but the nonce and `max_age`, and must name the
  original issuer, subject and tenant, and the original `auth_time` and
  `nonce` when it carries them (`oidc_refreshed_id_token_mismatch`).
  `TokenRequestRejected` now names the grant, and `refreshTokenInvalid()` tells
  a refresh token the provider no longer accepts.
- **Userinfo.** `UserInfoEndpoint::fetch($claims, $accessToken)` calls the
  userinfo endpoint with the access token and returns a `UserInfo`, refusing a
  response for another `sub` (`oidc_userinfo_subject_mismatch`), a 401 or 403
  (`UserInfoRejected`, `oidc_userinfo_rejected`, with the Bearer error) and a
  signed `application/jwt` response. A connection whose `groups.source` is
  `userinfo` now reads its groups there during the login callback;
  `CallbackResult::$userInfo` carries the response.
- **RP-initiated logout.** `LogoutFlow::start()` builds the logout request to
  the provider's `end_session_endpoint` with `client_id`, and `id_token_hint`,
  `post_logout_redirect_uri`, `state`, `logout_hint` and `ui_locales` from
  `LogoutOptions` or the connection; `redirect()` falls back to a URL of yours
  when the provider has no endpoint. The URL passes the SSRF guard's redirect
  check.
- **Token revocation.** `TokenRevocation::revoke()` revokes a refresh or
  access token (RFC 7009) with the connection's client authentication.
  Failures are `RevocationRejected` (`oidc_revocation_rejected`) and
  `ProviderUnavailable`.
- **Back-channel logout.** `LogoutTokenVerifier` verifies a logout token
  (OpenID Connect Back-Channel Logout 1.0): the ID token's form, signature,
  `iss`, `aud` and lifetime rules, a `typ` of `logout+jwt`, `JWT` or none, the
  back-channel logout event, no `nonce`, a `sub` or `sid`, and a `jti`
  accepted once, remembered in the cache until the token expires. Failures are
  `LogoutTokenRejected` (`oidc_logout_token_invalid`,
  `oidc_logout_token_replayed`), which extends `TokenRejected`. The opt-in
  route macro `Route::oidcBackChannelLogout()` registers a POST endpoint
  without CSRF verification that dispatches `BackChannelLogoutReceived` and
  answers 200, 400, 404 or 503 as the specification asks. `LogoutToken::matches()`
  tells whether a session's verified claims are meant.
- **Missing endpoints and bad arguments.** A call to an endpoint the provider
  does not advertise fails with `EndpointNotSupported`
  (`oidc_endpoint_not_supported`), and each service has `supported()`. A
  malformed token or scope passed to a method fails with `InvalidArgument`
  (`oidc_argument_invalid`).

### Fixed

- **Anchored patterns accepted a trailing newline.** A scope, connection name
  or number in `config/oidc.php` ending in a newline passed its check, because
  `$` in a PHP pattern also matches before a final newline. Every anchored
  pattern now uses the `D` modifier.

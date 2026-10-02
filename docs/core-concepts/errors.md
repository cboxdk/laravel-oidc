---
title: Errors
description: Every error code, what it means and whether a retry can help
weight: 24
---

# Errors

Every exception the package throws extends `Cbox\Oidc\Exceptions\OidcException`
and carries:

- `errorCode()`: a `Cbox\Oidc\Exceptions\ErrorCode`, whose value is stable and
  never renamed, so you can match on it in logs and alerts;
- `problem()`: what went wrong;
- `fix()`: one sentence that says what to change.

The message repeats all three, so a log line alone is enough:

```text
[oidc_discovery_issuer_mismatch] The discovery document of connection "main" names the issuer "https://login.example.com/", but the connection pins "https://login.example.com". They must be equal, character for character (RFC 8414 3.3). Fix: If "https://login.example.com/" is the provider you mean, set oidc.connections.main.issuer to it exactly, trailing slash included. Otherwise check discovery_url.
```

Messages never repeat a URL's query or user info, a response body, or a
secret.

| Code | Exception | Meaning | Retry? |
|---|---|---|---|
| `oidc_config_invalid` | `InvalidConfiguration` | A value in `config/oidc.php` is missing or invalid; `key()` names it. | No |
| `oidc_connection_unknown` | `UnknownConnection` | Code named a connection that is not configured. | No |
| `oidc_http_blocked` | `OutboundRequestBlocked` | The SSRF guard refused a URL: not https, or it resolves to a private, loopback or metadata address. | No |
| `oidc_provider_unavailable` | `ProviderUnavailable` | The provider could not be reached, timed out, or answered 408, 429 or 5xx. | Yes |
| `oidc_provider_response_invalid` | `InvalidProviderResponse` | The provider answered with another status, a redirect, a body over the size limit, or malformed JSON. | No |
| `oidc_discovery_issuer_mismatch` | `DiscoveryFailed` | The discovery document names another issuer than the connection pins. | No |
| `oidc_discovery_invalid` | `DiscoveryFailed` | The discovery document lacks a required member, or one is unusable for the connection. | No |
| `oidc_jwks_invalid` | `KeySetInvalid` | The key set is not `{"keys": [...]}`, or holds more than 100 keys. | No |
| `oidc_signing_key_not_found` | `SigningKeyNotFound` | No key matches the token's `kid`, or without a `kid` no single key fits. Rotation is handled for you; see [key rotation](discovery-and-keys.md#key-rotation). | After the cooldown |
| `oidc_signing_key_unsuitable` | `SigningKeyUnsuitable` | The key the token names may not verify it: wrong type, curve, size, use or alg. | No |
| `oidc_authorization_options_invalid` | `InvalidAuthorizationOptions` | An `AuthorizationOptions` value is invalid, such as `Prompt::None` with another prompt or a protocol parameter in `parameters`. | No |
| `oidc_state_mismatch` | `CallbackRejected` | The callback's state matches no login this session started for the connection: forged, used already, from another browser, or the session was lost on the way. | Start again |
| `oidc_transaction_expired` | `CallbackRejected` | The login was started longer ago than `oidc.flow.transaction_ttl_seconds`. | Start again |
| `oidc_callback_issuer_mismatch` | `CallbackRejected` | The callback's `iss` is missing although the provider announces it, or names another issuer (RFC 9207). | Start again |
| `oidc_callback_invalid` | `CallbackRejected` | The callback has no usable code, or a parameter in another form than one string. | Start again |
| `oidc_authorization_denied` | `AuthorizationDenied` | The provider answered with an OAuth error; `error()` gives the code, `interactionRequired()` tells a silent login that needs the person. | Start again |
| `oidc_token_request_rejected` | `TokenRequestRejected` | The token endpoint refused the request; `error()` gives the code, such as `invalid_grant` or `invalid_client`, and `refreshTokenInvalid()` tells a refresh token that is no longer valid. | Depends on the code |
| `oidc_token_malformed` | `TokenRejected` | The token is not a compact, signed JWT the package reads: too long, encrypted, a header or payload that is not a JSON object with unique keys, or `crit` or `b64` in the header. | No |
| `oidc_token_type_invalid` | `TokenRejected` | The token's `typ` is that of another kind of token, such as `logout+jwt`. | No |
| `oidc_token_algorithm_not_allowed` | `TokenRejected` | `alg` is `none`, `HS*`, or not one of the connection's algorithms that the provider lists. | No |
| `oidc_token_signature_invalid` | `TokenRejected` | The signature does not verify with the provider's key. | No |
| `oidc_token_issuer_mismatch` | `TokenRejected` | `iss` is not the pinned issuer (for Entra, with the token's `tid`), differs from the callback's `iss`, or from the signing key's issuer. | No |
| `oidc_token_audience_invalid` | `TokenRejected` | `aud` lacks the client id, or `azp` is missing with several audiences or names another client. | No |
| `oidc_token_expired` | `TokenRejected` | `exp` has passed, beyond the leeway. | Start again |
| `oidc_token_not_yet_valid` | `TokenRejected` | `nbf` or `iat` lies in the future, beyond the leeway: check the clock. | No |
| `oidc_token_stale` | `TokenRejected` | `iat` is older than `max_token_age_seconds`. | Start again |
| `oidc_token_claim_invalid` | `TokenRejected` | A required claim is missing (`sub`, `exp`, `iat`), or a claim has a form the protocol does not allow; `claim()` names it. | No |
| `oidc_id_token_nonce_mismatch` | `TokenRejected` | The ID token has no nonce, or not the nonce of this login. | Start again |
| `oidc_id_token_auth_time_invalid` | `TokenRejected` | `auth_time` is missing though `max_age` was sent, lies in the future, or is older than `max_age` allows. | Start again |
| `oidc_id_token_at_hash_mismatch` | `TokenRejected` | `at_hash` does not match the access token. | Start again |
| `oidc_tenant_claim_missing` | `TenantRejected` | The connection pins a tenant and the token has no tenant claim, such as a consumer Google account without `hd`. | No |
| `oidc_tenant_not_allowed` | `TenantRejected` | The token's tenant is not on the connection's allow-list, or `tid` is not a GUID. | No |
| `oidc_refreshed_id_token_mismatch` | `TokenRejected` | The ID token a refresh returned names another issuer, subject or tenant than the login it renews, or another `auth_time` or `nonce`. | Sign in again |
| `oidc_endpoint_not_supported` | `EndpointNotSupported` | The provider advertises no `userinfo_endpoint`, `end_session_endpoint` or `revocation_endpoint`; `endpoint()` names it. | No |
| `oidc_userinfo_rejected` | `UserInfoRejected` | The userinfo endpoint answered 401 or 403; `error()` gives the Bearer error, such as `invalid_token`. | After a refresh |
| `oidc_userinfo_subject_mismatch` | `UserInfoRejected` | The userinfo response names another `sub` than the ID token. | No |
| `oidc_revocation_rejected` | `RevocationRejected` | The revocation endpoint refused the request; `error()` gives the code, such as `unsupported_token_type`. | No |
| `oidc_argument_invalid` | `InvalidArgument` | A value passed to a method is malformed, such as an empty refresh token or a scope with a space. | No |
| `oidc_logout_options_invalid` | `InvalidLogoutOptions` | A `LogoutOptions` value is invalid, such as an `idTokenHint` that is not a JWT. | No |
| `oidc_logout_token_invalid` | `LogoutTokenRejected` | A logout token has no back-channel logout event, has a `nonce`, names neither `sub` nor `sid`, or has no `jti`. | No |
| `oidc_logout_token_replayed` | `LogoutTokenRejected` | A logout token with this `jti` was accepted already. | No |

`TokenRejected::claim()` names the claim or header member a token failure is
about, such as `exp` or `alg`. `TenantRejected` extends `TokenRejected`, so
catch it first when you want to tell a person that their organisation cannot
sign in. `LogoutTokenRejected` extends it too. See
[ID token verification](id-token-verification.md) and
[logout](logout.md#the-rules-a-logout-token-must-pass) for the order of the
checks.

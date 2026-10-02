---
title: Errors
description: Every error code, what it means and whether a retry can help
weight: 18
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
| `oidc_token_request_rejected` | `TokenRequestRejected` | The token endpoint refused the request; `error()` gives the code, such as `invalid_grant` or `invalid_client`. | Depends on the code |

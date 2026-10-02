---
title: Discovery and keys
description: How a connection's discovery document and signing keys are fetched, checked, cached and rotated
weight: 16
---

# Discovery and keys

Everything the package knows about a provider comes from two documents it
fetches itself: the discovery document and the key set. Both go through the
[HTTP client](../extension-points/http-client.md), so both pass the SSRF guard,
never follow a redirect and are capped at `oidc.http.max_response_bytes`.

## The discovery document

The document lives at the connection's `discovery_url` (by default the issuer
plus `/.well-known/openid-configuration`). `Cbox\Oidc\Discovery\MetadataRepository`
fetches it and `ProviderMetadata::fromDocument()` checks it against the
connection:

- The document is one JSON object, and no object in it has the same key twice.
  `json_decode()` keeps the last of two equal keys while another parser may
  keep the first, so a document with duplicates is refused.
- `issuer` equals the connection's issuer character for character (RFC 8414
  3.3, OpenID Connect Discovery 4.3). A trailing slash, another case or
  another tenant path is a mismatch: `oidc_discovery_issuer_mismatch`.
- `authorization_endpoint`, `token_endpoint` and `jwks_uri` are present, and
  every endpoint the document names is an absolute https URL.
- `id_token_signing_alg_values_supported` lists at least one algorithm the
  connection accepts. `ProviderMetadata::$signingAlgorithms` holds the common
  ones, in the connection's order.
- Where the document lists them, `response_types_supported` contains `code`,
  `code_challenge_methods_supported` contains `S256`, and
  `token_endpoint_auth_methods_supported` contains the connection's
  `client_auth`. Without that list a provider supports `client_secret_basic`
  only; a public client (`client_auth` `none`) is not checked.

Anything else that is wrong is `oidc_discovery_invalid`, with the member named
in the message.

## The key set

`Cbox\Oidc\Keys\KeySetRepository` fetches `jwks_uri` and reads it with
web-token. It holds at most 100 keys; keys without a `kty`, or that web-token
cannot read, are skipped, as RFC 7517 5 asks, and private members a provider
publishes by mistake are dropped.

`Cbox\Oidc\Keys\SigningKeys::find($connection, $algorithm, $kid)` returns the
one key that may verify a token, from the token header's `alg` and `kid`:

- With a `kid`, the key with that `kid`. Without one, the single key that fits
  the algorithm; when several fit, the package refuses rather than try them one
  by one.
- A key fits when its `use` is `sig` or absent, its `key_ops` (if any) allow
  `verify`, its `alg` (if any) is the token's, its `kty` is one web-token's
  algorithm takes, its `crv` is the algorithm's curve (P-256, P-384, P-521,
  Ed25519), and web-token's key analyzers find no serious flaw: RSA keys have
  at least 2048 bits and a public exponent of at least 65537, and EC points lie
  on their curve.
- A named key that does not fit is `oidc_signing_key_unsuitable`.
- Header members that carry or point to a key (`jwk`, `jku`, `x5u`, `x5c`) are
  never consulted.

## Key rotation

When the `kid` is not in the cached key set, the provider has probably rotated
its keys. The package then:

1. rereads the shared cache, in case another process fetched the new set;
2. refetches the key set, unless it was refetched within
   `jwks_refetch_cooldown_seconds` (60 by default) for this connection.

The cooldown is taken with an atomic `Cache::add()`, so it holds across
processes. A token with a made-up `kid` therefore costs at most one fetch per
cooldown, not one per login. Inside the cooldown the lookup fails with
`oidc_signing_key_not_found` and says so.

## Caching

Both documents are kept in the cache store `oidc.cache.store` (the default
store when null), with a copy per process:

| Document | Fresh for |
|---|---|
| Discovery | `discovery_ttl_seconds` (one day) |
| Key set | the provider's `Cache-Control: max-age`, clamped to `jwks_min_ttl_seconds` and `jwks_max_ttl_seconds`; `jwks_default_ttl_seconds` without one; `no-store` and `no-cache` count as the minimum |

A document is checked before it is cached, and again each time it is read, so
a change of the connection's configuration takes effect at once and a wrong
document is never kept.

When a document is stale and the refetch fails because the provider is
unavailable (a network error, a timeout, 408, 429 or a 5xx), the stale copy
stands in for up to `stale_if_error_seconds` more. A provider that answers
with a wrong document is never covered by a stale copy.

Freshness is decided by the package's PSR-20 clock. The default clock follows
Carbon, so `$this->travel()` in your tests moves it together with the cache.

Each process keeps its own copy of a document, and reads the cache store
again at least every five seconds, so a document dropped from the store is
dropped everywhere within seconds: also in Octane and queue workers that run
for hours. Drop a cached document, for example when a provider withdraws a
compromised key, from any process that shares the cache store (`artisan
tinker`, a command or a route). With the array or file store, which processes
do not share, run it in each.

<!-- example: forget-cache -->
```php
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Keys\KeySetRepository;

$connection = app(OidcConfig::class)->connection('main');
$metadata = app(MetadataRepository::class)->for($connection);

app(KeySetRepository::class)->forget($connection, $metadata);
app(MetadataRepository::class)->forget($connection);
```

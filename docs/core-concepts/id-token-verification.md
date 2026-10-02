---
title: ID token verification
description: Every rule an ID token must pass, the tenant policies for Google and Microsoft Entra, and the verified claims you get back
weight: 18
---

# ID token verification

`callback()` verifies the ID token of every login before it returns, and
gives you the result as `$result->claims`, a `Cbox\Oidc\Tokens\VerifiedClaims`.
Nothing in it comes from an unverified token.

The crypto is [web-token](https://web-token.spomky-labs.com): it parses the
keys, verifies the signature and runs the `iss`, `aud`, `azp`, `exp`, `nbf`
and `iat` checks with the package's PSR-20 clock. The package adds the rules
of OpenID Connect that web-token leaves to the relying party, and decides the
order.

## The rules, in order

The first rule a token breaks throws a `TokenRejected` with its own code, and
`claim()` names the claim or header member to blame.

| # | Rule | Code |
|---|---|---|
| 1 | At most 16 KiB; a compact JWS of three base64url parts in canonical encoding. JWE and the JSON serialization are refused, so `alg` cannot hide in an unprotected header. | `oidc_token_malformed` |
| 2 | The header is a JSON object with unique keys, without `crit` or `b64`. | `oidc_token_malformed` |
| 3 | `typ`, when present, is not the type of another kind of token (anything ending in `+jwt`, such as `logout+jwt` or `at+jwt`). | `oidc_token_type_invalid` |
| 4 | `alg` is one of the connection's `algorithms` that the provider also lists. `none` and `HS*` can never be configured, so a token that uses them is always refused, including an `HS256` token keyed with the provider's public key. | `oidc_token_algorithm_not_allowed` |
| 5 | The key comes from the provider's key set by `kid`, and must fit `alg`; see [discovery and keys](discovery-and-keys.md). `jwk`, `jku`, `x5u` and `x5c` in the header are never used. | `oidc_signing_key_not_found`, `oidc_signing_key_unsuitable` |
| 6 | The signature verifies, with an algorithm manager that holds only that one algorithm. | `oidc_token_signature_invalid` |
| 7 | The payload is a JSON object with unique keys. | `oidc_token_malformed` |
| 8 | `iss` is the pinned issuer, character for character. With an Entra `{tenantid}` issuer, it is the template with the token's `tid` filled in. It equals the callback's `iss` parameter when there was one, and the `issuer` of the signing key when the key has one. | `oidc_token_issuer_mismatch` |
| 9 | `aud` contains the `client_id`. With more than one audience, `azp` is required; `azp`, when present, is the `client_id`. | `oidc_token_audience_invalid` |
| 10 | `exp` is present and not passed; `nbf`, when present, and `iat` are not in the future. Each allows `leeway_seconds`. | `oidc_token_expired`, `oidc_token_not_yet_valid` |
| 11 | `iat` is at most `max_token_age_seconds` (plus the leeway) ago. | `oidc_token_stale` |
| 12 | `nonce` is the nonce of this login, compared in constant time. | `oidc_id_token_nonce_mismatch` |
| 13 | `sub` is 1 to 255 characters, without control characters. | `oidc_token_claim_invalid` |
| 14 | `auth_time` is not in the future. When the login sent `max_age`, it is required and at most `max_age` (plus the leeway) ago. | `oidc_id_token_auth_time_invalid` |
| 15 | `at_hash`, when present, is the left half of the hash of the access token: SHA-256, -384 or -512 after the algorithm, and SHA-512 for EdDSA. | `oidc_id_token_at_hash_mismatch` |
| 16 | The tenant claim is present and allowed (see below). | `oidc_tenant_claim_missing`, `oidc_tenant_not_allowed` |
| 17 | `amr` and `groups` are lists of strings; `acr` and `sid` are strings. | `oidc_token_claim_invalid` |

Times are whole seconds from the clock you bind to `Psr\Clock\ClockInterface`
(Carbon's by default, so `$this->travel()` moves it in tests). A token is
accepted until `exp` plus the leeway, inclusive.

## Tenants

A connection with a `tenant` policy only accepts tokens whose tenant claim is
present and listed. `TenantRejected` extends `TokenRejected`, so you can catch
it first and tell the person that their organisation cannot sign in, as the
[login routes](login-flow.md#routes) do.

**Google Workspace.** Pin the `hd` claim to your domains. A consumer Google
account has no `hd` and is refused with `oidc_tenant_claim_missing`. Domains
are compared without case; a subdomain is another domain. The `hd` request
parameter is only a hint to Google's account chooser and is never trusted.

```php
'tenant' => ['claim' => 'hd', 'allowed' => ['example.com', 'example.org']],
```

**Microsoft Entra, one tenant.** Use the tenant's own issuer and discovery
document (`https://login.microsoftonline.com/<tenant id>/v2.0`), and pin `tid`
as well.

**Microsoft Entra, several tenants.** Use the `{tenantid}` issuer template
with the `organizations` (or `common`) discovery document, and list the
tenants:

```php
'issuer' => 'https://login.microsoftonline.com/{tenantid}/v2.0',
'discovery_url' => 'https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration',
'tenant' => ['claim' => 'tid', 'allowed' => ['<tenant id>', '<tenant id>']],
```

The token's `tid` must be a GUID; the expected issuer is the template with
that `tid` filled in, so a token whose `iss` names one tenant and whose `tid`
names another is refused. Entra puts the issuer template on each key of its
key set, and a key may only sign tokens of its own issuer. `['*']` accepts any
tenant on purpose, the personal Microsoft account tenant
(`9188040d-6c67-4c5b-b112-36a304b66dad`) included; with a list, a personal
account is refused unless its tenant is listed. Version 1 tokens
(`https://sts.windows.net/...`) never match a v2.0 issuer.

**Other providers.** Any claim can be pinned, such as an organisation id;
values other than `hd` and `tid` are compared exactly.

## The verified claims

| Property or method | From |
|---|---|
| `connection` | the connection's name |
| `issuer`, `subject` | `iss`, `sub`: identify the person by both together |
| `audience`, `authorizedParty` | `aud` as a list, `azp` |
| `issuedAt`, `expiresAt`, `authTime` | `iat`, `exp`, `auth_time` as `DateTimeImmutable` (UTC) |
| `authenticationMethods` | `amr`, each method once, or null |
| `authenticationContext` | `acr`, or null |
| `sessionId` | `sid`, or null; back-channel logout names sessions by it |
| `tenant` | the value of the pinned tenant claim, or null without a policy |
| `groups`, `groupsOverage` | see below |
| `email()`, `emailVerified()`, `name()` | `email`, `email_verified` (true only for the JSON value `true`), `name` |
| `claim($name, $default)`, `string($name)`, `has($name)`, `all()` | any claim as sent |

Match accounts on issuer and subject, never on email: an email address can
change hands, and some providers let people set it without proof.

**Groups.** With `groups.source` `id_token` (the default), `groups` is the
configured claim as a list, each group once, or `[]` when the token has none.
When Microsoft Entra leaves the groups out because there are too many (the
overage: `_claim_names` names the claim), `groups` is null and
`groupsOverage` is true. Do not treat that as "no groups", which would take
roles away; fetch them from Microsoft Graph or refuse the login. With source
`userinfo` or `none`, `groups` is null.

## Verifying a token yourself

`callback()` is the usual way in. When an ID token reaches you another way,
such as from a mobile app that signed in with a nonce your server issued,
verify it with `IdTokenVerifier`. Always pass the nonce you expect; null
turns the nonce check off and lets a captured token be replayed until it
expires.

<!-- example: verify-id-token -->
```php
<?php

use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;

// $idToken came from the app; $nonce is the one your server gave it.
$claims = app(IdTokenVerifier::class)->verify('main', $idToken, new IdTokenExpectations(nonce: $nonce));

return [$claims->issuer, $claims->subject];
```

`IdTokenExpectations` also takes `maxAge`, `accessToken` (checked against
`at_hash`) and `responseIssuer` (the callback's `iss`);
`IdTokenExpectations::forLogin($transaction, $accessToken, $iss)` builds them
from a started login.

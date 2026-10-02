---
title: Security
description: Reporting vulnerabilities, and what the package does and does not protect
weight: 30
---

# Security

## Reporting

Report vulnerabilities privately through
[GitHub Private Vulnerability Reporting](https://github.com/cboxdk/laravel-oidc/security/advisories/new),
as [SECURITY.md](../../SECURITY.md) describes. Token verification bypasses are
the class of report we most want.

## What the configuration already prevents

- `alg: none` and the `HS*` algorithms cannot be configured for ID tokens.
- The issuer must be https, without a query or fragment, so it can be compared
  exactly with the provider's metadata.
- A Microsoft Entra issuer template (`{tenantid}`) cannot be configured without
  a tenant policy on `tid`; accepting any tenant takes an explicit `['*']`.
- Protocol parameters the package sets itself (`state`, `nonce`, the PKCE
  challenge, `redirect_uri` and others) cannot be overridden through
  `authorization_parameters`.
- `redirect_uri` and `post_logout_redirect_uri` must be https, except on
  `localhost`, a loopback address or a name below `.localhost` or `.test`, so
  a code never crosses the network unencrypted (RFC 6749 3.1.2.1).
- Two connections cannot share a `redirect_uri`.
- The client secret is redacted when a connection is dumped.

## What the HTTP layer prevents

- Every call to a provider, including the URLs a discovery document names,
  passes the `cboxdk/laravel-ssrf` guard: https only, and no private, loopback
  or metadata address. The guard checks the URL actually sent and pins the
  resolved address.
- Redirects are never followed, and bodies are capped at
  `oidc.http.max_response_bytes`. Bodies are never decompressed, so a small
  gzip response cannot expand past the cap.
- A discovery document must name exactly the configured issuer, and every
  endpoint in it must be https.
- JSON with the same key twice is refused, so the package and the provider
  cannot read one document two ways.
- Keys come from the provider's key set only. Header members that carry or
  point to a key (`jwk`, `jku`, `x5u`, `x5c`) are never used, a key must fit
  the algorithm (type, curve, at least 2048-bit RSA, EC points on the curve),
  and an unknown `kid` refetches the key set at most once per cooldown.

## What the login flow prevents

- **Login CSRF and injected codes.** Every login gets a fresh 256-bit state,
  kept server-side under its SHA-256 and compared in constant time. A callback
  is accepted only for a login this session started for this connection, once,
  and within `oidc.flow.transaction_ttl_seconds`. The state is checked before
  anything else, so a forged code or error is refused without a call to the
  provider.
- **Client assertions for the wrong party.** A `private_key_jwt` assertion
  names the URL it is sent to (or the issuer) as `aud`, so a provider that
  advertises another provider's token endpoint never receives an assertion
  that provider accepts. `oidc:check` warns when two connections share a key.
- **Stolen codes.** PKCE with S256 is always sent, also by confidential
  clients; the verifier never leaves the server except to the token endpoint.
- **Replayed ID tokens.** A fresh nonce per login must come back in the ID
  token, compared in constant time, and the token may be at most
  `max_token_age_seconds` old.
- **Mix-up attacks.** Two connections cannot share a `redirect_uri`, and a
  callback must arrive at the host and path of its login's `redirect_uri`, so
  a response meant for one connection is never finished by another, also when
  the provider sends no `iss`. The `iss` parameter (RFC 9207) must be the
  pinned issuer whenever the callback carries it or the provider announces
  it.
- **Injected text.** Only the OAuth error code of an error answer is read, and
  only when it is letters, digits, dots, dashes and underscores;
  `error_description` never reaches a message, log or page.
- **Open redirects.** The authorization URL is built from the checked
  discovery document and passes the SSRF guard's redirect check.
- Tokens, the nonce, the PKCE verifier and private keys are redacted when
  dumped.

## What ID token verification prevents

- **Forged tokens.** Only compact JWS is read, so `alg` cannot hide in an
  unprotected header (the web-token advisory GHSA-jc38-x7x8-2xc8). `none` and
  `HS*` are never accepted, which also closes the confusion where an `HS256`
  token is keyed with the provider's public key. Each signature is verified
  with an algorithm manager that holds only the token's one allowed algorithm.
- **Tokens of another kind.** A `typ` that names another kind of token (such
  as `logout+jwt`) is refused, as are `crit` and `b64`.
- **Tokens for someone else.** `iss` must be the pinned issuer exactly, and
  equal the callback's `iss`; `aud` must contain the client id, with `azp`
  required for several audiences.
- **Cross-tenant logins.** For an Entra `{tenantid}` issuer, `tid` must be a
  GUID, the issuer is checked with that `tid` filled in, the signing key's own
  issuer must match, and the tenant must be on the allow-list. A Google
  Workspace connection requires the `hd` claim; the `hd` request parameter is
  never trusted.
- **Swapped access tokens.** `at_hash`, when present, must match the access
  token, with the hash of the signing algorithm (SHA-512 for EdDSA).
- **Stale sign-ins.** With `max_age`, `auth_time` is required and checked.
- **Stripped step-up.** When a login sends `acr_values`, they are kept with the
  login and the ID token's `acr` must be one of them, so removing them from the
  URL in the browser does not turn a step-up into a single-factor login.
- Exceptions name the rule and the claim, never a token or the nonce. The few
  values they repeat (an issuer, a tenant, an `alg`, a `typ`) are shortened,
  with control characters replaced.

## What refresh, userinfo and revocation prevent

- **A refresh that swaps the person.** An ID token a refresh returns passes
  every ID token rule, and must name the original issuer, subject and tenant,
  and the original `auth_time` and `nonce` when it carries them (OpenID
  Connect Core 12.2).
- **Userinfo for someone else.** The userinfo response's `sub` must be the ID
  token's subject (OpenID Connect Core 5.3.4); a mismatch fails the call, and
  a login that reads groups from userinfo fails with it.
- The refresh token, access token and revocation token travel only to the
  provider's advertised https endpoints through the SSRF guard, and are
  redacted when dumped.

## What logout prevents

- **Open redirects.** The logout URL is built from the checked discovery
  document and passes the SSRF guard's redirect check; a
  `post_logout_redirect_uri` must be an absolute https URL (http only on a
  local host).
- **Forged logout tokens.** A logout token passes the same form, `alg`, key,
  signature, `iss`, `aud` and lifetime rules as an ID token.
- **An ID token used to sign its owner out.** A logout token must carry the
  back-channel logout event and must not carry a `nonce`, which every ID token
  of a login has; an ID token's `typ` and a logout token's are told apart too.
- **Replayed logout tokens.** Each `jti` is accepted once, remembered with an
  atomic cache add until the token's `exp` plus the leeway. A token refused
  for another reason does not use up its `jti`, and a failed listener gives
  it back so the provider can retry.
- **Tokens in logs.** A refused logout token is logged with its code and
  rule, never the token; the 400 answer names only the code.

## Testing and diagnostics

- **The fake is for tests only.** `Oidc::fake()` lives in
  `Cbox\Oidc\Testing` and reports through PHPUnit. Its ID tokens are
  unsecured JWTs (`alg: none`) that the package's verifier refuses as
  malformed, so a token the fake made can never pass a real check. It
  replaces the client only for the application instance of the test that
  called it.
- **`oidc:check` calls the provider like a login does.** The discovery
  document and key set are fetched through the same client and SSRF guard and
  checked by the same rules; the cache is not touched. The output names the issuer,
  client id, endpoints and key ids, never the client secret or a private key,
  and provider text is printed as text, not as console markup.

## Honest scope

- The package is a relying party. It issues no tokens.
- Encrypted ID tokens (JWE), signed userinfo, pushed authorization requests
  (PAR), DPoP and the form_post response mode are not part of 0.1.
  Front-channel logout is not supported.
- Google documents that `iss` may also be `accounts.google.com` without the
  scheme. Only the configured issuer (`https://accounts.google.com`) is
  accepted; Google's code flow returns that form.
- A token is accepted until `exp` plus the leeway, inclusive (web-token's
  rule), one second more than RFC 7519 strictly allows.
- Microsoft Entra v2.0 tokens may lack `auth_time`. With `max_age` such a
  login is refused.
- The default transaction store trusts the Laravel session. A session that
  cannot reach the callback (a `SameSite=strict` cookie) makes every login
  fail closed with `oidc_state_mismatch`.
- A logout token typed `JWT`, or not typed, is accepted, because providers
  that predate explicit typing send those; the event and the ban on `nonce`
  keep an ID token out.
- The `jti` of logout tokens is only as shared as the cache store of
  `oidc.cache.store`. With the array or file store, each server remembers its
  own.
- The package verifies a logout token and tells you; ending the sessions it
  names is up to the application, which knows where its sessions live. The
  [logout page](../core-concepts/logout.md#back-channel-logout) shows one way.
- The tenant allow-list is not applied to logout tokens, which end sessions
  rather than start them.
- Refresh tokens are as safe as the place you keep them. Encrypt the session
  (`session.encrypt`) or the token itself.
- The SSRF guard is defence in depth; a network egress allow-list is the only
  complete control.
- `oidc:check` does not try the client secret or private key, and cannot see
  the redirect URIs registered at the provider; both show at the first login.

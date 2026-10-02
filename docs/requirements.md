---
title: Requirements
description: PHP, Laravel and extension versions cboxdk/laravel-oidc needs
weight: 3
---

# Requirements

Taken from the package's `composer.json`, which the resolver enforces; this
page only explains it.

## Runtime

| Requirement | Version | Why |
|---|---|---|
| PHP | `^8.4` | Uses PHP 8.4 language features. CI runs 8.4 and 8.5. |
| `ext-json` | any | Discovery documents, key sets and token responses are JSON. |
| `ext-openssl` | any | RSA and ECDSA signatures (RS*, PS*, ES*). |
| `ext-sodium` | any | EdDSA (Ed25519) signatures. |

`ext-gmp` (or `ext-bcmath`) is suggested: it speeds up the big-number arithmetic
behind key handling.

## Framework

| Requirement | Version |
|---|---|
| Laravel (`illuminate/contracts`, `illuminate/http`, `illuminate/support`) | `^12.0 \|\| ^13.0` |

Registered through package auto-discovery, so no manual provider wiring.

## Libraries

| Package | Version | Why |
|---|---|---|
| `web-token/jwt-library` | `^4.2.3` | JWK and JWKS parsing, signature verification and claim checks. 4.2.3 includes the fixes for the June 2026 advisories. |
| `cboxdk/laravel-ssrf` | `^1.5` | Guards every outbound call to a provider. |
| `guzzlehttp/guzzle` | `^7.8.2 \|\| ^8.0` | The transport under Laravel's HTTP client; the size limit uses its `on_headers` and `progress` options. |
| `psr/clock` | `^1.0` | Time comes from a PSR-20 clock, so tests can freeze it. |

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
  and carries an `ErrorCode` and a `fix()`.

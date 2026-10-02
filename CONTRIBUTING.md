# Contributing

Thanks for helping. Bug reports, fixes and documentation improvements are all
welcome. Security issues go through [SECURITY.md](SECURITY.md), never a public
issue.

## Process

1. Fork the repository and branch from `main`.
2. Make the change, with tests.
3. Run `composer qa`: Pint, Rector, PHPStan at level max, the Pest suites, the
   license check and `composer audit`. Every step must pass. With PCOV or
   Xdebug installed, `composer test:coverage` also holds line coverage of
   `src` at 99%, as CI does.
4. Open a pull request that explains why the change is needed, not only what it
   does.

## Ground rules

- New behaviour needs tests. A bug fix needs a regression test that fails
  without the fix.
- A change to the public API updates the documentation in `docs/` and the
  [changelog](CHANGELOG.md) in the same pull request. The public API is what
  [docs/index.md](docs/index.md#the-public-api) lists; a class that is not part
  of it carries `@internal`, and no documentation sample may use one.
- No `@phpstan-ignore`, no baseline, and no loosened checks to make a build pass.
- Cryptography and token parsing stay in `web-token/jwt-library`. Do not
  hand-write signature checks, key parsing or base64url JSON decoding of tokens.
- Every outbound HTTP call goes through the injected client, so the SSRF guard
  sees it. No direct `curl_*`, sockets or URL wrappers.
- Time comes from the PSR-20 clock, never from `time()` or `now()`, so tests can
  freeze it.
- A new dependency needs a reason and a permissive license (`composer
  license-check`), and regenerates `sbom.json` (`composer sbom`).

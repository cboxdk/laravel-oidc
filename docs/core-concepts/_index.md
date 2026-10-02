---
title: Core concepts
description: How the package talks to a provider, caches what it learns and names what goes wrong
weight: 15
---

# Core concepts

- **[Discovery and keys](discovery-and-keys.md)** — How a connection's discovery document and signing keys are fetched, checked, cached and rotated
- **[The login flow](login-flow.md)** — Start a login, handle the callback, and what each step checks
- **[ID token verification](id-token-verification.md)** — Every rule an ID token must pass, tenant pinning for Google and Entra, and the verified claims
- **[Refresh and userinfo](refresh-and-userinfo.md)** — Renew a login's tokens with its refresh token, and read the person's claims from the userinfo endpoint
- **[Logout](logout.md)** — End the session at the provider, revoke its tokens, and receive back-channel logout from the provider
- **[Errors](errors.md)** — Every error code, what it means and whether a retry can help

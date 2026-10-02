---
title: Keycloak
description: Sign in through a Keycloak realm, with groups and back-channel logout
weight: 44
---

# Keycloak

Create a client of type OpenID Connect in your realm, with "Standard flow"
and "Client authentication" on. Add `https://app.example.com/oidc/callback` as
a valid redirect URI, and copy the secret from the client's Credentials tab:

<!-- example: provider-keycloak -->
```dotenv
# Keycloak before version 17 adds /auth: https://sso.example.com/auth/realms/staff.
OIDC_ISSUER=https://sso.example.com/realms/staff
OIDC_CLIENT_ID=my-app
OIDC_CLIENT_SECRET=secret-from-the-credentials-tab
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
OIDC_POST_LOGOUT_REDIRECT_URI=https://app.example.com/
```

For refresh tokens that outlive the Keycloak session, set in
`connections.main` of `config/oidc.php`:

<!-- example: provider-keycloak-config -->
```php
<?php

// config/oidc.php, in connections.main
return [
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],
    // The realm's keys decide; RS256 is the default.
    'algorithms' => ['RS256', 'ES256', 'EdDSA'],
];
```

For a public client without a secret, turn "Client authentication" off and
set `'client_auth' => 'none'`; PKCE then binds the code to the login.

## What to know

- **Groups.** Add a "Group Membership" mapper to the client's dedicated
  scope, with token claim name `groups` and "Add to ID token" on. Turn "Full
  group path" off to get `staff` rather than `/staff`.
- **Signing.** Keycloak signs with the realm's active key, RS256 unless you
  add an ECDSA or EdDSA key provider. List what your realm uses in
  `algorithms`.
- **Refresh.** Keycloak issues refresh tokens with every login;
  `offline_access` makes them outlive the Keycloak session.
- **Logout and revocation.** Keycloak lists both endpoints.
- **Back-channel logout.** Set the client's "Backchannel logout URL" to your
  receiver, such as `https://app.example.com/oidc/main/backchannel-logout`
  (see [back-channel logout](../core-concepts/logout.md#back-channel-logout)),
  and turn "Backchannel logout session required" on to receive `sid`.

## Local development

Keycloak in Docker answers on `http://127.0.0.1:8080`, without TLS. Two
switches let the package call it, and both are for your machine only:

- `allow_insecure_http` (`OIDC_ALLOW_INSECURE_HTTP`) lets the issuer and the
  realm's endpoints be plain http. The package refuses it unless `APP_ENV` is
  `local` or `testing`, and `oidc:check` warns while it is on.
- `SSRF_ENFORCE=false` turns off the SSRF guard's address checks, which
  refuse loopback and private addresses. Use `127.0.0.1` rather than
  `localhost`: the guard refuses the name `localhost` even then.

Start Keycloak with `docker run -p 8080:8080 -e KC_BOOTSTRAP_ADMIN_USERNAME=admin
-e KC_BOOTSTRAP_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak start-dev`,
create a realm and a confidential client, and open the app at
`http://127.0.0.1:8000`, so the realm's issuer and the redirect URI use the
same host as the calls. Then, in `.env`:

<!-- example: keycloak-local-env -->
```dotenv
APP_ENV=local
OIDC_ISSUER=http://127.0.0.1:8080/realms/dev
OIDC_ALLOW_INSECURE_HTTP=true
OIDC_CLIENT_ID=my-app
OIDC_CLIENT_SECRET=secret-from-the-credentials-tab
OIDC_REDIRECT_URI=http://127.0.0.1:8000/oidc/callback
SSRF_ENFORCE=false
```

Keep these lines out of every other environment's `.env`.

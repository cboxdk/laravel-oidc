---
title: Auth0
description: Sign in through an Auth0 tenant
weight: 45
---

# Auth0

Create an application of type "Regular Web Application". Add
`https://app.example.com/oidc/callback` under Allowed Callback URLs and your
logout URL under Allowed Logout URLs.

<!-- example: provider-auth0 -->
```dotenv
# Auth0's issuer ends in a slash; write it exactly so.
OIDC_ISSUER=https://example-tenant.eu.auth0.com/
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
OIDC_POST_LOGOUT_REDIRECT_URI=https://app.example.com/
```

For refresh tokens and roles, set in `connections.main` of `config/oidc.php`:

<!-- example: provider-auth0-config -->
```php
<?php

// config/oidc.php, in connections.main
return [
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],
    // A namespaced claim that an Auth0 Action adds.
    'groups' => ['source' => 'id_token', 'claim' => 'https://app.example.com/roles'],
];
```

## What to know

- **Issuer.** Auth0's issuer has a trailing slash, and the package compares
  issuers exactly. Without the slash, discovery fails with
  `oidc_discovery_issuer_mismatch`. With a custom domain, the issuer is that
  domain, also with the slash.
- **Signing.** Set the application's JSON Web Token signature algorithm to
  RS256 (Advanced settings, OAuth). HS256 tokens are never accepted.
- **Groups and roles.** Auth0 puts none in the ID token. A post-login Action
  can add them under a namespaced claim, such as
  `api.idToken.setCustomClaim('https://app.example.com/roles', event.authorization.roles)`;
  name that claim in `groups.claim`.
- **Refresh.** Enable the Refresh Token grant on the application and request
  `offline_access`.
- **Logout.** Auth0 announces its `end_session_endpoint` when the tenant
  setting "RP-Initiated Logout End Session Endpoint Discovery" is on.
  `Oidc::logout()` falls back to your URL when it is not.
- **Revocation and back-channel logout.** Check what your tenant announces
  with `oidc:check`.

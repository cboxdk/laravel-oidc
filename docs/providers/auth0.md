---
title: Auth0
description: Sign in through an Auth0 tenant
weight: 45
---

# Auth0

Create an application of type "Regular Web Application". Add the callback URL
under Allowed Callback URLs and the logout URL under Allowed Logout URLs.

<!-- example: provider-auth0 -->
```php
<?php

return [
    'default' => 'auth0',
    'connections' => [
        'auth0' => [
            // Auth0's issuer ends in a slash; write it exactly so.
            'issuer' => 'https://example-tenant.eu.auth0.com/',
            'client_id' => env('AUTH0_CLIENT_ID', 'auth0-client-id'),
            'client_secret' => env('AUTH0_CLIENT_SECRET', 'auth0-client-secret'),
            'redirect_uri' => 'https://app.example.com/oidc/auth0/callback',
            'scopes' => ['openid', 'profile', 'email', 'offline_access'],
            'algorithms' => ['RS256'],
            // A namespaced claim that an Auth0 Action adds.
            'groups' => ['source' => 'id_token', 'claim' => 'https://app.example.com/roles'],
            'post_logout_redirect_uri' => 'https://app.example.com/',
        ],
    ],
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

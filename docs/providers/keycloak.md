---
title: Keycloak
description: Sign in through a Keycloak realm, with groups and back-channel logout
weight: 44
---

# Keycloak

Create a client of type OpenID Connect in your realm, with "Standard flow"
on. Add the callback URL as a valid redirect URI. Turn "Client
authentication" on for a confidential client with a secret, or leave it off
for a public client that relies on PKCE alone, as below.

<!-- example: provider-keycloak -->
```php
<?php

return [
    'default' => 'keycloak',
    'connections' => [
        'keycloak' => [
            // Keycloak before version 17 adds /auth: https://sso.example.com/auth/realms/staff.
            'issuer' => 'https://sso.example.com/realms/staff',
            'client_id' => env('KEYCLOAK_CLIENT_ID', 'cms'),
            'client_auth' => 'none',
            'redirect_uri' => 'https://app.example.com/oidc/keycloak/callback',
            'scopes' => ['openid', 'profile', 'email', 'offline_access'],
            // The realm's keys decide; RS256 is the default.
            'algorithms' => ['RS256', 'ES256', 'EdDSA'],
            'groups' => ['source' => 'id_token', 'claim' => 'groups'],
            'post_logout_redirect_uri' => 'https://app.example.com/',
        ],
    ],
];
```

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
  receiver, such as `https://app.example.com/oidc/keycloak/backchannel-logout`
  (see [back-channel logout](../core-concepts/logout.md#back-channel-logout)),
  and turn "Backchannel logout session required" on to receive `sid`.

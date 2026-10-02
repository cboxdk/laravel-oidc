---
title: Okta
description: Sign in through an Okta authorization server
weight: 43
---

# Okta

Create an app integration of type "OIDC - OpenID Connect", "Web Application".
Add the callback URL as a sign-in redirect URI and the logout URL as a
sign-out redirect URI. Tick "Refresh Token" under grant types for refresh
tokens.

<!-- example: provider-okta -->
```php
<?php

return [
    'default' => 'okta',
    'connections' => [
        'okta' => [
            // The default custom authorization server. For the org
            // authorization server, the issuer is https://example.okta.com.
            'issuer' => 'https://example.okta.com/oauth2/default',
            'client_id' => env('OKTA_CLIENT_ID', '0oa1example2client3id'),
            'client_secret' => env('OKTA_CLIENT_SECRET', 'okta-client-secret'),
            'redirect_uri' => 'https://app.example.com/oidc/okta/callback',
            'scopes' => ['openid', 'profile', 'email', 'offline_access'],
            'algorithms' => ['RS256'],
            'groups' => ['source' => 'id_token', 'claim' => 'groups'],
            'post_logout_redirect_uri' => 'https://app.example.com/',
        ],
    ],
];
```

## What to know

- **Issuer.** Copy it from the authorization server's settings in Okta. A
  custom authorization server's issuer ends in `/oauth2/<id>`; the org
  authorization server's issuer is the Okta domain itself. They sign with
  different keys, so use the one your app is set up for.
- **Groups.** Okta sends no groups by default. On a custom authorization
  server, add a claim named `groups` of value type Groups, included in the ID
  token always, with a filter such as "Matches regex .*". On the org
  authorization server, set the app's groups claim filter and add `groups` to
  `scopes`. The claim must be a list of strings.
- **Signing.** RS256.
- **Refresh.** Request `offline_access` and enable the Refresh Token grant.
  Okta can rotate refresh tokens; always keep `$renewed->refreshToken`.
- **Logout and revocation.** Okta lists both endpoints.
- **Back-channel logout.** Check what your org announces with `oidc:check`.

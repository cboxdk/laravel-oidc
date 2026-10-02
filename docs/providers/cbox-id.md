---
title: Cbox ID
description: Sign in through a Cbox ID instance
weight: 46
---

# Cbox ID

Register an OAuth client on your Cbox ID instance with the callback URL as a
redirect URI.

<!-- example: provider-cbox-id -->
```php
<?php

return [
    'default' => 'cbox',
    'connections' => [
        'cbox' => [
            'issuer' => env('CBOX_ID_ISSUER', 'https://id.example.com'),
            'client_id' => env('CBOX_ID_CLIENT_ID', 'cid_example'),
            'client_secret' => env('CBOX_ID_CLIENT_SECRET', 'csec_example'),
            'redirect_uri' => 'https://app.example.com/oidc/cbox/callback',
            'scopes' => ['openid', 'profile', 'email', 'offline_access'],
            'algorithms' => ['RS256'],
            'groups' => ['source' => 'none'],
            'post_logout_redirect_uri' => 'https://app.example.com/',
        ],
    ],
];
```

## What to know

- **This package or the Cbox ID client.** This package signs people in
  through Cbox ID like through any other provider. For organisations, roles,
  permissions, API keys and management calls, use
  [`cboxdk/laravel-id-client`](https://github.com/cboxdk/laravel-id-client),
  which is built for Cbox ID.
- **Signing.** Cbox ID signs ID tokens with RS256.
- **Refresh.** Request `offline_access`.
- **Logout and revocation.** Cbox ID lists both endpoints.
- **Back-channel logout.** Cbox ID sends logout tokens with `sid` to the
  client's back-channel logout URI; see
  [back-channel logout](../core-concepts/logout.md#back-channel-logout).

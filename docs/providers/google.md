---
title: Google
description: Sign in with Google accounts, and pin Google Workspace domains
weight: 41
---

# Google

Create an OAuth client of type "Web application" in the Google Cloud console,
under APIs & Services, Credentials. Add the callback URL as an authorized
redirect URI, exactly as in `redirect_uri`.

<!-- example: provider-google -->
```php
<?php

return [
    'default' => 'google',
    'connections' => [
        'google' => [
            'issuer' => 'https://accounts.google.com',
            'client_id' => env('GOOGLE_CLIENT_ID', 'google-client-id.apps.googleusercontent.com'),
            'client_secret' => env('GOOGLE_CLIENT_SECRET', 'google-client-secret'),
            'redirect_uri' => 'https://app.example.com/oidc/google/callback',
            'scopes' => ['openid', 'email', 'profile'],
            'algorithms' => ['RS256'],
            // Only people of these Workspace domains. Leave tenant out to
            // accept every Google account, personal ones included.
            'tenant' => ['claim' => 'hd', 'allowed' => ['example.com']],
            'groups' => ['source' => 'none'],
            // Google issues a refresh token only with access_type=offline,
            // and again after the first consent only with prompt=consent.
            'authorization_parameters' => [
                'access_type' => 'offline',
                'prompt' => 'consent',
            ],
        ],
    ],
];
```

## What to know

- **Issuer.** `https://accounts.google.com`. Google documents that `iss` may
  also be `accounts.google.com` without the scheme; only the configured form is
  accepted, and Google's code flow sends that one.
- **Workspace domains.** The `hd` claim names the person's Workspace domain.
  A personal account has no `hd` and is refused with
  `oidc_tenant_claim_missing`; a person of another domain with
  `oidc_tenant_not_allowed`. The `hd` request parameter only steers Google's
  account chooser and is never trusted.
- **Signing.** Google signs ID tokens with RS256 only.
- **Groups.** Google puts no groups in its ID tokens, so `groups.source` is
  `none`. Read group memberships through the Admin SDK if you need them.
- **Refresh.** See `authorization_parameters` above. `prompt=consent` shows
  the consent screen at every login; drop it once you store refresh tokens and
  only need one the first time.
- **Logout.** Google has no `end_session_endpoint`, so `Oidc::logout()`
  sends the browser to your fallback URL and the Google session stays.
  `Oidc::revoke()` works: Google lists a `revocation_endpoint`.
- **Back-channel logout.** Not offered by Google.

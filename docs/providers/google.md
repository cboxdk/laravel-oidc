---
title: Google
description: Sign in with Google accounts, and pin Google Workspace domains
weight: 41
---

# Google

Create an OAuth client of type "Web application" in the Google Cloud console,
under APIs & Services, Credentials. Add `https://app.example.com/oidc/callback`
as an authorized redirect URI, then put the client in `.env`:

<!-- example: provider-google -->
```dotenv
OIDC_ISSUER=https://accounts.google.com
OIDC_CLIENT_ID=1234567890-abc123.apps.googleusercontent.com
OIDC_CLIENT_SECRET=GOCSPX-your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
```

That is all a "Sign in with Google" needs; the published defaults do the rest.

## Only your Workspace domains

To let in only people of your Google Workspace domains, pin the `hd` claim in
`connections.main` of `config/oidc.php`:

<!-- example: provider-google-workspace -->
```php
<?php

// config/oidc.php, in connections.main
return [
    // Leave tenant out to accept every Google account, personal ones included.
    'tenant' => ['claim' => 'hd', 'allowed' => ['example.com']],
];
```

## Refresh tokens

Google issues a refresh token only with `access_type=offline`:

<!-- example: provider-google-refresh -->
```php
<?php

// config/oidc.php, in connections.main
return [
    'authorization_parameters' => ['access_type' => 'offline'],
];
```

Google sends the refresh token at the first consent only. When you need one
for a person whose token you do not hold, ask for consent on that login
alone, rather than with `prompt => consent` in the configuration, which shows
the consent screen at every sign-in:

<!-- example: provider-google-consent -->
```php
<?php

use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\Prompt;

return Oidc::redirect(options: new AuthorizationOptions(prompt: Prompt::Consent));
```

## What to know

- **Issuer.** `https://accounts.google.com`. Google documents that `iss` may
  also be `accounts.google.com` without the scheme; only the configured form is
  accepted, and Google's code flow sends that one.
- **Workspace domains.** The `hd` claim names the person's Workspace domain.
  With the pin above, a personal account has no `hd` and is refused with
  `oidc_tenant_claim_missing`, and a person of another domain with
  `oidc_tenant_not_allowed`. The `hd` request parameter only steers Google's
  account chooser and is never trusted.
- **Signing.** Google signs ID tokens with RS256.
- **Groups.** Google puts no groups in its ID tokens, so `$claims->groups` is
  an empty list. Read group memberships through the Admin SDK if you need
  them.
- **Email.** `email_verified` is true for Google accounts; check
  `$claims->emailVerified()` before you trust `$claims->email()` all the same.
- **Logout.** Google has no `end_session_endpoint`, so `Oidc::logout()`
  sends the browser to your fallback URL and the Google session stays.
  `Oidc::revoke()` works: Google lists a `revocation_endpoint`.
- **Back-channel logout.** Not offered by Google.

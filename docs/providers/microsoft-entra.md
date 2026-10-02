---
title: Microsoft Entra ID
description: Sign in through one Entra tenant, or several tenants with an allow-list
weight: 42
---

# Microsoft Entra ID

Register an application under Entra ID, App registrations. Add
`https://app.example.com/oidc/callback` as a "Web" redirect URI and create a
client secret (or upload a certificate for `private_key_jwt`, see
[client authentication](../core-concepts/login-flow.md#client-authentication)).
Use the v2.0 endpoints; the package does not read v1.0 tokens.

## One tenant

The application lives in your tenant, and only its accounts sign in
("Accounts in this organizational directory only"). The issuer carries your
directory (tenant) ID:

<!-- example: provider-entra-single -->
```dotenv
OIDC_ISSUER=https://login.microsoftonline.com/3f2504e0-4f89-41d3-9a0c-0305e82c3301/v2.0
OIDC_CLIENT_ID=00000000-0000-0000-0000-000000000001
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
OIDC_POST_LOGOUT_REDIRECT_URI=https://app.example.com/
```

Pin the same tenant in `connections.main` of `config/oidc.php`, and ask for
refresh tokens:

<!-- example: provider-entra-single-config -->
```php
<?php

// config/oidc.php, in connections.main
return [
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],
    'tenant' => ['claim' => 'tid', 'allowed' => ['3f2504e0-4f89-41d3-9a0c-0305e82c3301']],
];
```

## Several tenants

The application is multi-tenant ("Accounts in any organizational directory").
The issuer is the `{tenantid}` template, the discovery document is the
`organizations` one, and the `tid` claim must be on your allow-list. The
issuer is checked with the token's `tid` filled in.

<!-- example: provider-entra-multi -->
```dotenv
OIDC_ISSUER=https://login.microsoftonline.com/{tenantid}/v2.0
OIDC_DISCOVERY_URL=https://login.microsoftonline.com/organizations/v2.0/.well-known/openid-configuration
OIDC_CLIENT_ID=00000000-0000-0000-0000-000000000001
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=https://app.example.com/oidc/callback
```

<!-- example: provider-entra-multi-config -->
```php
<?php

// config/oidc.php, in connections.main
return [
    'scopes' => ['openid', 'profile', 'email', 'offline_access'],
    'tenant' => [
        'claim' => 'tid',
        'allowed' => [
            '11111111-1111-1111-1111-111111111111',
            '22222222-2222-2222-2222-222222222222',
        ],
    ],
];
```

A `{tenantid}` issuer without a tenant pin on `tid` is refused. `['*']`
instead of the list accepts every tenant, the personal Microsoft account
tenant included; `oidc:check` warns about it, because it is rarely what you
want.

## What to know

- **Tenant.** `tid` must be a GUID on the list, compared without case. A
  token whose `iss` names one tenant and whose `tid` names another is refused,
  and so is a key that Entra's key set marks for another issuer.
- **Groups.** Add a groups claim under Token configuration. Entra then puts
  group object IDs in `groups`. A person in more groups than fit in a token
  gets none ("group overage"): `$claims->groups` is null and
  `$claims->groupsOverage` is true, and you read the groups from Microsoft
  Graph.
- **Email.** Entra's `email` claim is optional and not verified; a tenant
  administrator can set it to anything. Never match accounts on it.
- **Refresh.** Request `offline_access`, as above.
- **`max_age`.** Entra v2.0 ID tokens may lack `auth_time`. With `max_age`
  set, such a login is refused with `oidc_id_token_auth_time_invalid`.
- **acr values.** Entra ignores `acr_values` (it uses `claims` and the `acrs`
  claim), so do not pass `acrValues`: the login would fail with
  `oidc_id_token_acr_mismatch`.
- **Logout.** Entra has an `end_session_endpoint`. Register
  `post_logout_redirect_uri` as one of the app's redirect URIs.
- **Revocation and back-channel logout.** Entra announces neither in its
  discovery document; `oidc:check` shows what your tenant announces.

---
title: Transaction store
description: Keep started logins somewhere other than the Laravel session
weight: 27
---

# Transaction store

Between `start()` and `callback()`, a login waits as an
`AuthorizationTransaction`: the connection, the state, the nonce, the PKCE
verifier, the redirect URI, the `max_age` it asked for and when it started.
It is kept by `Cbox\Oidc\Contracts\TransactionStore`:

<!-- signature: Cbox\Oidc\Contracts\TransactionStore -->
```php
public function put(AuthorizationTransaction $transaction): void;

public function pull(string $state): ?AuthorizationTransaction;
```

The default, `Cbox\Oidc\Flow\SessionTransactionStore`, keeps transactions in
the Laravel session of the current request, under the SHA-256 of each state.
It drops transactions older than `oidc.flow.transaction_ttl_seconds` and keeps
at most `oidc.flow.max_pending_transactions`, newest first. The login and
callback routes therefore need the `web` middleware group.

## Your own store

Bind your own implementation in a service provider; the package binds the
session store only when nothing else is bound:

<!-- example: transaction-store-binding -->
```php
use Cbox\Oidc\Contracts\TransactionStore;

$this->app->singleton(TransactionStore::class, MyTransactionStore::class);
```

It must keep the rules the flow relies on:

- **Secret.** The nonce and the PKCE verifier must not reach the browser in
  readable form: keep them server-side, or encrypt and authenticate them.
- **Bound to the browser.** A transaction started in one browser must not be
  found from another, or the state no longer stops login CSRF.
- **Once.** `pull()` returns a transaction at most once and removes it.
- **Exact.** Look a transaction up by its full state, compared in constant
  time; `AuthorizationTransaction::toArray()` and `fromArray()` give a form to
  store. The flow checks the age and the connection itself.

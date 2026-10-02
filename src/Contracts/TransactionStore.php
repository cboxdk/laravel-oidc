<?php

declare(strict_types=1);

namespace Cbox\Oidc\Contracts;

use Cbox\Oidc\Flow\AuthorizationTransaction;
use Cbox\Oidc\Flow\SessionTransactionStore;

/**
 * Keeps started logins until their callback.
 *
 * The default, {@see SessionTransactionStore}, keeps them in the Laravel
 * session, so the login and callback routes need the web middleware group.
 * Bind your own to keep them elsewhere, such as an encrypted cookie for an
 * application without sessions. It must keep the same rules:
 *
 * - server-side or tamper-proof: the nonce and PKCE verifier are secrets;
 * - bound to the browser that started the login;
 * - {@see self::pull()} gives an entry once and removes it.
 */
interface TransactionStore
{
    public function put(AuthorizationTransaction $transaction): void;

    /**
     * The transaction started with $state, removed from the store; null when
     * there is none.
     */
    public function pull(string $state): ?AuthorizationTransaction;
}

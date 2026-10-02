<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Config\FlowConfig;
use Cbox\Oidc\Contracts\TransactionStore;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Session\Session;
use Psr\Clock\ClockInterface;

/**
 * The default {@see TransactionStore}: the Laravel session of the current
 * request.
 *
 * Each started login is kept under the SHA-256 of its state, so several
 * logins (one per open tab) can wait at once. Expired ones are dropped, and
 * at most oidc.flow.max_pending_transactions are kept, newest first.
 */
final readonly class SessionTransactionStore implements TransactionStore
{
    public const string SESSION_KEY = 'oidc_transactions';

    public function __construct(
        private Container $container,
        private FlowConfig $flow,
        private ClockInterface $clock,
    ) {}

    public function put(AuthorizationTransaction $transaction): void
    {
        $oldest = $this->clock->now()->getTimestamp() - $this->flow->transactionTtlSeconds;
        $entries = array_filter(
            $this->entries(),
            static fn (array $entry): bool => is_int($entry['created_at'] ?? null) && $entry['created_at'] >= $oldest,
        );

        $entries[$this->key($transaction->state)] = $transaction->toArray();
        $entries = array_slice($entries, -$this->flow->maxPendingTransactions, null, true);

        $this->session()->put(self::SESSION_KEY, $entries);
    }

    public function pull(string $state): ?AuthorizationTransaction
    {
        $entries = $this->entries();
        $key = $this->key($state);

        if (! array_key_exists($key, $entries)) {
            return null;
        }

        $transaction = AuthorizationTransaction::fromArray($entries[$key]);
        unset($entries[$key]);
        $this->session()->put(self::SESSION_KEY, $entries);

        return $transaction instanceof AuthorizationTransaction && hash_equals($transaction->state, $state) ? $transaction : null;
    }

    /**
     * @return array<string, array<array-key, mixed>>
     */
    private function entries(): array
    {
        $stored = $this->session()->get(self::SESSION_KEY);
        $entries = [];

        if (! is_array($stored)) {
            return [];
        }

        foreach ($stored as $key => $entry) {
            if (is_string($key) && is_array($entry)) {
                $entries[$key] = $entry;
            }
        }

        return $entries;
    }

    private function session(): Session
    {
        // Resolved per call: the session belongs to the current request.
        return $this->container->make(Session::class);
    }

    private function key(string $state): string
    {
        return hash('sha256', $state);
    }
}

<?php

declare(strict_types=1);

use Cbox\Oidc\Config\FlowConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\TransactionStore;
use Cbox\Oidc\Flow\AuthorizationTransaction;
use Cbox\Oidc\Flow\SessionTransactionStore;
use Illuminate\Contracts\Session\Session;

beforeEach(function (): void {
    $this->freezeSecond();
    $this->store = fn (): TransactionStore => resolve(TransactionStore::class);
    $this->make = static fn (string $state, int $age = 0): AuthorizationTransaction => new AuthorizationTransaction('main', $state, 'n-'.$state, 'v-'.$state, 'https://app.example.test/oidc/callback', null, now()->getTimestamp() - $age);
});

it('is the default store', function (): void {
    expect(($this->store)())->toBeInstanceOf(SessionTransactionStore::class);
});

it('gives a transaction back once', function (): void {
    ($this->store)()->put(($this->make)('a'));

    expect(($this->store)()->pull('a')?->nonce)->toBe('n-a')
        ->and(($this->store)()->pull('a'))->toBeNull()
        ->and(($this->store)()->pull('b'))->toBeNull();
});

it('keeps the states out of the session keys', function (): void {
    ($this->store)()->put(($this->make)('a-secret-state'));

    expect(array_keys((array) resolve(Session::class)->get(SessionTransactionStore::SESSION_KEY)))->toBe([hash('sha256', 'a-secret-state')]);
});

it('keeps the newest transactions up to the limit', function (): void {
    config(['oidc.flow.max_pending_transactions' => 2]);
    app()->forgetInstance(OidcConfig::class);
    app()->forgetInstance(FlowConfig::class);
    app()->forgetInstance(TransactionStore::class);

    foreach (['a', 'b', 'c'] as $state) {
        ($this->store)()->put(($this->make)($state));
    }

    expect(($this->store)()->pull('a'))->toBeNull()
        ->and(($this->store)()->pull('b'))->not->toBeNull()
        ->and(($this->store)()->pull('c'))->not->toBeNull();
});

it('drops expired transactions when it stores a new one', function (): void {
    ($this->store)()->put(($this->make)('old', 601));
    ($this->store)()->put(($this->make)('new'));

    expect(array_keys((array) resolve(Session::class)->get(SessionTransactionStore::SESSION_KEY)))->toBe([hash('sha256', 'new')]);
});

it('reads a damaged session entry as no transaction', function (): void {
    resolve(Session::class)->put(SessionTransactionStore::SESSION_KEY, [hash('sha256', 'a') => ['state' => 'a'], 7 => 'junk']);

    expect(($this->store)()->pull('a'))->toBeNull();

    resolve(Session::class)->put(SessionTransactionStore::SESSION_KEY, 'junk');

    expect(($this->store)()->pull('a'))->toBeNull();

    ($this->store)()->put(($this->make)('b'));

    expect(($this->store)()->pull('b')?->state)->toBe('b');
});

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use SensitiveParameter;

/**
 * What one started login keeps until its callback: the state that binds the
 * callback to this browser, the nonce the ID token must repeat, the PKCE
 * verifier for the code exchange, and what the request asked for.
 *
 * It lives server-side, in the session by default, and is used once.
 */
final readonly class AuthorizationTransaction
{
    public function __construct(
        public string $connection,
        public string $state,
        #[SensitiveParameter] public string $nonce,
        #[SensitiveParameter] public string $codeVerifier,
        public string $redirectUri,
        public ?int $maxAge,
        public int $createdAt,
    ) {}

    /**
     * The array form a {@see TransactionStore} keeps.
     *
     * @return array{connection: string, state: string, nonce: string, code_verifier: string, redirect_uri: string, max_age: int|null, created_at: int}
     */
    public function toArray(): array
    {
        return [
            'connection' => $this->connection,
            'state' => $this->state,
            'nonce' => $this->nonce,
            'code_verifier' => $this->codeVerifier,
            'redirect_uri' => $this->redirectUri,
            'max_age' => $this->maxAge,
            'created_at' => $this->createdAt,
        ];
    }

    /**
     * Reads {@see self::toArray()}'s form back; null for anything else, so a
     * damaged entry counts as no entry.
     */
    public static function fromArray(mixed $values): ?self
    {
        if (! is_array($values)) {
            return null;
        }

        $strings = [];

        foreach (['connection', 'state', 'nonce', 'code_verifier', 'redirect_uri'] as $key) {
            if (! isset($values[$key]) || ! is_string($values[$key]) || $values[$key] === '') {
                return null;
            }

            $strings[$key] = $values[$key];
        }

        $maxAge = $values['max_age'] ?? null;
        $createdAt = $values['created_at'] ?? null;

        if (($maxAge !== null && ! is_int($maxAge)) || ! is_int($createdAt)) {
            return null;
        }

        return new self($strings['connection'], $strings['state'], $strings['nonce'], $strings['code_verifier'], $strings['redirect_uri'], $maxAge, $createdAt);
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'connection' => $this->connection,
            'state' => $this->state,
            'nonce' => '[redacted]',
            'codeVerifier' => '[redacted]',
            'redirectUri' => $this->redirectUri,
            'maxAge' => $this->maxAge,
            'createdAt' => $this->createdAt,
        ];
    }
}

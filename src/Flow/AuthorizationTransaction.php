<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use SensitiveParameter;

/**
 * What one started login keeps until its callback: the state that binds the
 * callback to this browser, the nonce the ID token must repeat, the PKCE
 * verifier for the code exchange, and what the request asked for (max_age
 * and acr_values, which the ID token must then satisfy).
 *
 * It lives server-side, in the session by default, and is used once.
 */
final readonly class AuthorizationTransaction
{
    /**
     * @param  list<string>  $acrValues  the acr_values the login sent; the ID token's acr must be one of them
     */
    public function __construct(
        public string $connection,
        public string $state,
        #[SensitiveParameter] public string $nonce,
        #[SensitiveParameter] public string $codeVerifier,
        public string $redirectUri,
        public ?int $maxAge,
        public int $createdAt,
        public array $acrValues = [],
    ) {}

    /**
     * The array form a {@see TransactionStore} keeps.
     *
     * @return array{connection: string, state: string, nonce: string, code_verifier: string, redirect_uri: string, max_age: int|null, created_at: int, acr_values: list<string>}
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
            'acr_values' => $this->acrValues,
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

        $acrValues = $values['acr_values'] ?? [];

        if (! is_array($acrValues) || ! array_is_list($acrValues)) {
            return null;
        }

        $acr = [];

        foreach ($acrValues as $value) {
            if (! is_string($value) || $value === '') {
                return null;
            }

            $acr[] = $value;
        }

        return new self($strings['connection'], $strings['state'], $strings['nonce'], $strings['code_verifier'], $strings['redirect_uri'], $maxAge, $createdAt, $acr);
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
            'acrValues' => $this->acrValues,
        ];
    }
}

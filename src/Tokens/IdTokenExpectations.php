<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Flow\AuthorizationTransaction;
use SensitiveParameter;

/**
 * What an ID token must match besides the connection's own rules: the values
 * of the request that produced it.
 *
 * - $nonce: the nonce the login sent. The token must carry it. Null only
 *   where no nonce was sent; a login always sends one.
 * - $maxAge: the max_age the login sent. auth_time then becomes required and
 *   must be within it.
 * - $accessToken: the access token that came with the ID token, checked
 *   against at_hash when the token has one.
 * - $responseIssuer: the callback's iss parameter (RFC 9207), which must then
 *   be the token's iss.
 */
final readonly class IdTokenExpectations
{
    public function __construct(
        #[SensitiveParameter] public ?string $nonce,
        public ?int $maxAge = null,
        #[SensitiveParameter] public ?string $accessToken = null,
        public ?string $responseIssuer = null,
    ) {}

    /**
     * The expectations of the login $transaction started.
     */
    public static function forLogin(AuthorizationTransaction $transaction, #[SensitiveParameter] ?string $accessToken = null, ?string $responseIssuer = null): self
    {
        return new self($transaction->nonce, $transaction->maxAge, $accessToken, $responseIssuer);
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'nonce' => $this->nonce === null ? null : '[redacted]',
            'maxAge' => $this->maxAge,
            'accessToken' => $this->accessToken === null ? null : '[redacted]',
            'responseIssuer' => $this->responseIssuer,
        ];
    }
}

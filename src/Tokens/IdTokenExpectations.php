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
 * - $renews: for a token a refresh returned, the claims of the login it
 *   renews; issuer, subject, tenant, auth_time and nonce must then match
 *   them (OpenID Connect Core 12.2).
 * - $acrValues: the acr_values the login sent. The token's acr must then be
 *   one of them (OpenID Connect Core 3.1.3.7 step 11), so a step-up a
 *   browser stripped from the request is not accepted as single-factor.
 */
final readonly class IdTokenExpectations
{
    /**
     * @param  list<string>  $acrValues
     */
    public function __construct(
        #[SensitiveParameter] public ?string $nonce,
        public ?int $maxAge = null,
        #[SensitiveParameter] public ?string $accessToken = null,
        public ?string $responseIssuer = null,
        public ?VerifiedClaims $renews = null,
        public array $acrValues = [],
    ) {}

    /**
     * The expectations of the login $transaction started.
     */
    public static function forLogin(AuthorizationTransaction $transaction, #[SensitiveParameter] ?string $accessToken = null, ?string $responseIssuer = null): self
    {
        return new self($transaction->nonce, $transaction->maxAge, $accessToken, $responseIssuer, acrValues: $transaction->acrValues);
    }

    /**
     * The expectations of an ID token a refresh returned: it renews the login
     * of $original, needs no nonce (but must repeat the original's when it
     * has one) and no max_age.
     */
    public static function forRefresh(VerifiedClaims $original, #[SensitiveParameter] ?string $accessToken = null): self
    {
        return new self(null, null, $accessToken, null, $original);
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
            'renews' => $this->renews instanceof VerifiedClaims ? $this->renews->issuer.' '.$this->renews->subject : null,
            'acrValues' => $this->acrValues,
        ];
    }
}

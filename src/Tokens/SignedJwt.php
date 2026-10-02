<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Jose\Component\Core\JWK;

/**
 * A compact JWS whose signature verified with the provider's key. Its claims
 * are not checked yet: that is the job of the verifier for its kind.
 *
 * @internal
 */
final readonly class SignedJwt
{
    /**
     * @param  array<string, mixed>  $header  the protected header
     * @param  array<string, mixed>  $claims  the payload
     */
    public function __construct(
        public array $header,
        public array $claims,
        public SigningAlgorithm $algorithm,
        public JWK $key,
    ) {}
}

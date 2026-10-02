<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Jose\Component\Signature\Algorithm\EdDSA;
use Jose\Component\Signature\Algorithm\ES256;
use Jose\Component\Signature\Algorithm\ES384;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Algorithm\PS256;
use Jose\Component\Signature\Algorithm\PS384;
use Jose\Component\Signature\Algorithm\PS512;
use Jose\Component\Signature\Algorithm\RS256;
use Jose\Component\Signature\Algorithm\RS384;
use Jose\Component\Signature\Algorithm\RS512;
use Jose\Component\Signature\Algorithm\SignatureAlgorithm;

/**
 * The asymmetric JWS algorithms a connection may accept for ID tokens.
 *
 * There is deliberately no case for none or the HS* family: an ID token signed
 * with a shared secret, or not at all, is never accepted.
 */
enum SigningAlgorithm: string
{
    case RS256 = 'RS256';
    case RS384 = 'RS384';
    case RS512 = 'RS512';
    case PS256 = 'PS256';
    case PS384 = 'PS384';
    case PS512 = 'PS512';
    case ES256 = 'ES256';
    case ES384 = 'ES384';
    case ES512 = 'ES512';
    case EdDSA = 'EdDSA';

    /**
     * The names accepted in configuration, in declaration order.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_map(static fn (self $algorithm): string => $algorithm->value, self::cases());
    }

    /**
     * web-token's implementation of this algorithm, which verifies signatures
     * and knows the key types (kty) the algorithm takes.
     */
    public function signatureAlgorithm(): SignatureAlgorithm
    {
        return match ($this) {
            self::RS256 => new RS256,
            self::RS384 => new RS384,
            self::RS512 => new RS512,
            self::PS256 => new PS256,
            self::PS384 => new PS384,
            self::PS512 => new PS512,
            self::ES256 => new ES256,
            self::ES384 => new ES384,
            self::ES512 => new ES512,
            self::EdDSA => new EdDSA,
        };
    }

    /**
     * The JWK curve (crv) a key must have for this algorithm, or null for the
     * RSA algorithms. EdDSA is Ed25519 only: Ed448 is not supported by
     * ext-sodium and so not by web-token.
     */
    public function curve(): ?string
    {
        return match ($this) {
            self::ES256 => 'P-256',
            self::ES384 => 'P-384',
            self::ES512 => 'P-521',
            self::EdDSA => 'Ed25519',
            default => null,
        };
    }
}

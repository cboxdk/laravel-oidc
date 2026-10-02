<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

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
}

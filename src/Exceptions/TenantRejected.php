<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

use Cbox\Oidc\Tokens\TokenKind;

/**
 * The token verified, but its tenant is not one the connection allows: a
 * Google account outside your Workspace domains (hd), or a Microsoft Entra
 * tenant (tid) not on the allow-list.
 *
 * Catch it apart from other {@see TokenRejected} failures to tell the person
 * that their organisation cannot sign in here.
 */
class TenantRejected extends TokenRejected
{
    public static function missing(string $connection, string $claim, TokenKind $kind = TokenKind::IdToken): self
    {
        return static::make(
            ErrorCode::TenantClaimMissing,
            sprintf('The %s of connection "%s" has no %s claim, and the connection only accepts named tenants.', $kind->label(), $connection, $claim),
            $claim === 'hd'
                ? 'The person signed in with a consumer Google account, not one of a Workspace domain. Ask them to use their work account.'
                : sprintf('The person\'s account belongs to no tenant the provider names in %s. Check the provider, and oidc.connections.%s.tenant.claim.', $claim, $connection),
            $claim,
        );
    }

    public static function notAllowed(string $connection, string $claim, string $tenant): self
    {
        return static::make(
            ErrorCode::TenantNotAllowed,
            sprintf('The ID token of connection "%s" belongs to the tenant %s "%s", which the connection does not allow.', $connection, $claim, self::shorten($tenant)),
            sprintf('If this organisation may sign in, add "%s" to oidc.connections.%s.tenant.allowed.', self::shorten($tenant), $connection),
            $claim,
        );
    }

    public static function invalidTenant(string $connection, string $claim, string $problem, TokenKind $kind = TokenKind::IdToken): self
    {
        return static::make(
            ErrorCode::TenantNotAllowed,
            sprintf('The %s of connection "%s" has a %s claim that %s.', $kind->label(), $connection, $claim, $problem),
            'The token does not name a tenant in the form the provider uses. Do not accept it.',
            $claim,
        );
    }
}

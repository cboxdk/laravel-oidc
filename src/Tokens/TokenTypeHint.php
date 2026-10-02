<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

/**
 * The token_type_hint of a revocation request (RFC 7009 2.1): which kind of
 * token is being revoked, so the provider looks it up first.
 */
enum TokenTypeHint: string
{
    case AccessToken = 'access_token';
    case RefreshToken = 'refresh_token';
}

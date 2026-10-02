<?php

declare(strict_types=1);

namespace Cbox\Oidc\UserInfo;

use Cbox\Oidc\Tokens\Concerns\ReadsClaims;

/**
 * The claims the userinfo endpoint returned for the person (OpenID Connect
 * Core 5.3.2). Its subject is the ID token's: the package refuses a response
 * for anyone else.
 *
 * These claims are not signed; they are as trustworthy as the TLS connection
 * to the provider. Identify the person by the ID token's issuer and subject,
 * never by a userinfo claim.
 */
final readonly class UserInfo
{
    use ReadsClaims;

    /**
     * @param  list<string>|null  $groups  the groups claim of the connection, when its groups.source is userinfo; null otherwise
     * @param  array<string, mixed>  $claims  every claim, as sent
     */
    public function __construct(
        public string $connection,
        public string $subject,
        public ?array $groups,
        public array $claims,
    ) {}
}

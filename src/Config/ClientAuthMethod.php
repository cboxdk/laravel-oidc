<?php

declare(strict_types=1);

namespace Cbox\Oidc\Config;

/**
 * How the client authenticates at the token, revocation and introspection
 * endpoints (OpenID Connect Core 9).
 */
enum ClientAuthMethod: string
{
    /** HTTP Basic with the client id and secret (the default). */
    case ClientSecretBasic = 'client_secret_basic';

    /** The client id and secret in the form body. */
    case ClientSecretPost = 'client_secret_post';

    /**
     * A JWT signed with the client's private key (RFC 7523), as Microsoft
     * Entra with certificates and Okta prefer. No shared secret.
     */
    case PrivateKeyJwt = 'private_key_jwt';

    /** A public client: no secret, PKCE alone binds the code. */
    case None = 'none';

    public function needsSecret(): bool
    {
        return $this === self::ClientSecretBasic || $this === self::ClientSecretPost;
    }

    /**
     * The values accepted in configuration.
     *
     * @return list<string>
     */
    public static function names(): array
    {
        return array_map(static fn (self $method): string => $method->value, self::cases());
    }
}

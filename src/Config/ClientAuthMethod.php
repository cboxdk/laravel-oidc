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

    /** A public client: no secret, PKCE alone binds the code. */
    case None = 'none';

    public function needsSecret(): bool
    {
        return $this !== self::None;
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc;

use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationRequest;
use Cbox\Oidc\Flow\CallbackResult;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use SensitiveParameter;

/**
 * The calls of an {@see OidcClient}, bound to one connection:
 *
 *     Oidc::connection('google')->redirect();
 *     Oidc::connection('google')->callback();
 *
 * Refresh and userinfo are not here: they take the verified claims of a
 * login, which name their connection already.
 */
final readonly class OidcConnection
{
    public function __construct(
        private OidcClient $client,
        public string $name,
    ) {}

    /**
     * @throws OidcException
     */
    public function start(?AuthorizationOptions $options = null): AuthorizationRequest
    {
        return $this->client->start($this->name, $options);
    }

    /**
     * @throws OidcException
     */
    public function redirect(?AuthorizationOptions $options = null): RedirectResponse
    {
        return $this->client->redirect($this->name, $options);
    }

    /**
     * @throws OidcException
     */
    public function callback(?Request $request = null): CallbackResult
    {
        return $this->client->callback($this->name, $request);
    }

    /**
     * @throws OidcException
     */
    public function logout(?LogoutOptions $options = null, string $fallback = '/'): RedirectResponse
    {
        return $this->client->logout($this->name, $options, $fallback);
    }

    /**
     * @throws OidcException
     */
    public function revoke(#[SensitiveParameter] string $token, ?TokenTypeHint $hint = TokenTypeHint::RefreshToken): void
    {
        $this->client->revoke($token, $hint, $this->name);
    }
}

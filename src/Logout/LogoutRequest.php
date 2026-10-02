<?php

declare(strict_types=1);

namespace Cbox\Oidc\Logout;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\RedirectResponse;

/**
 * A logout to finish at the provider: the URL of its end_session_endpoint
 * with the logout parameters. Return it from a controller and Laravel
 * answers with the redirect.
 */
final readonly class LogoutRequest implements Responsable
{
    public function __construct(
        public string $connection,
        public string $url,
    ) {}

    public function redirect(): RedirectResponse
    {
        return new RedirectResponse($this->url);
    }

    public function toResponse($request): RedirectResponse
    {
        return $this->redirect();
    }
}

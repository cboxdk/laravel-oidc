<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\RedirectResponse;

/**
 * A started login: the URL to send the browser to. Return it from a
 * controller and Laravel answers with the redirect.
 */
final readonly class AuthorizationRequest implements Responsable
{
    public function __construct(
        public string $connection,
        public string $url,
        public string $state,
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

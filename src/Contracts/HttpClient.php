<?php

declare(strict_types=1);

namespace Cbox\Oidc\Contracts;

use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Http\HttpResponse;
use Cbox\Oidc\Http\LaravelHttpClient;

/**
 * Every call the package makes to a provider (discovery, keys, token,
 * userinfo, revocation) goes through this one method.
 *
 * The default, {@see LaravelHttpClient}, sends through
 * Laravel's HTTP client behind the cboxdk/laravel-ssrf guard. Bind your own
 * implementation to route the calls elsewhere, for example through a
 * corporate egress proxy; it must keep the same rules:
 *
 * - https only, and the URL checked against SSRF before it is sent;
 * - redirects never followed (a 3xx comes back as a response);
 * - the body capped at the configured size, and never decompressed (a
 *   compressed body can expand past the cap).
 */
interface HttpClient
{
    /**
     * @throws OutboundRequestBlocked when the URL may not be called
     * @throws ProviderUnavailable on a network failure or timeout
     * @throws InvalidProviderResponse when the body exceeds the size limit
     */
    public function send(HttpRequest $request): HttpResponse;
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Logout;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\DiscoveryFailed;
use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Http\RedirectResponse;

/**
 * RP-initiated logout (OpenID Connect RP-Initiated Logout 1.0): sends the
 * browser to the provider's end_session_endpoint so the person's session
 * there ends too.
 *
 * End your own session first (Auth::logout(), invalidate the session), then
 * redirect with {@see self::start()} or {@see self::redirect()}. Not every
 * provider has the endpoint: Google has none. {@see self::supported()} tells,
 * and {@see self::redirect()} falls back to a URL of yours.
 *
 * The request carries client_id, and id_token_hint, post_logout_redirect_uri
 * (the option, else the connection's), state, logout_hint and ui_locales when
 * set. The endpoint keeps its own query, and must pass the SSRF guard's
 * redirect check (https).
 */
final readonly class LogoutFlow
{
    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private UrlGuard $guard,
    ) {}

    /**
     * Whether the connection's provider advertises an end_session_endpoint.
     *
     * @throws OidcException when the configuration or discovery fails
     */
    public function supported(?string $connection = null): bool
    {
        return $this->metadata->for($this->config->connection($connection))->endSessionEndpoint !== null;
    }

    /**
     * The logout request to send the browser to.
     *
     * @throws EndpointNotSupported when the provider has no end_session_endpoint
     * @throws OutboundRequestBlocked when the endpoint fails the SSRF guard
     * @throws OidcException when the configuration or discovery fails
     */
    public function start(?string $connection = null, LogoutOptions $options = new LogoutOptions): LogoutRequest
    {
        $config = $this->config->connection($connection);
        $endpoint = $this->metadata->for($config)->endSessionEndpoint
            ?? throw EndpointNotSupported::missing($config->name, 'end_session_endpoint', 'End the session in your application only; the provider cannot be asked to end its own. Use LogoutFlow::redirect() with a fallback URL, or check supported() first.');

        $url = $this->url($config, $endpoint, $options);

        try {
            $this->guard->assertSafeRedirect($url, ['https']);
        } catch (BlockedUrl $exception) {
            throw OutboundRequestBlocked::redirect($url, $exception);
        }

        return new LogoutRequest($config->name, $url);
    }

    /**
     * The redirect to the provider's logout, or to $fallback when the
     * provider has no end_session_endpoint.
     *
     * @throws OutboundRequestBlocked when the endpoint fails the SSRF guard
     * @throws OidcException when the configuration or discovery fails
     */
    public function redirect(?string $connection = null, LogoutOptions $options = new LogoutOptions, string $fallback = '/'): RedirectResponse
    {
        return $this->supported($connection)
            ? $this->start($connection, $options)->redirect()
            : new RedirectResponse($fallback);
    }

    private function url(ConnectionConfig $config, string $endpoint, LogoutOptions $options): string
    {
        $parameters = ['client_id' => $config->clientId];

        if ($options->idTokenHint !== null) {
            $parameters['id_token_hint'] = $options->idTokenHint;
        }

        $postLogout = $options->postLogoutRedirectUri ?? $config->postLogoutRedirectUri;

        if ($postLogout !== null) {
            $parameters['post_logout_redirect_uri'] = $postLogout;
        }

        if ($options->state !== null) {
            $parameters['state'] = $options->state;
        }

        if ($options->logoutHint !== null) {
            $parameters['logout_hint'] = $options->logoutHint;
        }

        if ($options->uiLocales !== []) {
            $parameters['ui_locales'] = implode(' ', $options->uiLocales);
        }

        $query = parse_url($endpoint, PHP_URL_QUERY);

        if (is_string($query) && $query !== '') {
            parse_str($query, $existing);
            $twice = array_intersect(array_map(strtolower(...), array_map(strval(...), array_keys($existing))), array_keys($parameters));

            if ($twice !== []) {
                throw DiscoveryFailed::invalid($config->name, $config->discoveryUrl, sprintf('has an end_session_endpoint whose query already sets %s', implode(', ', $twice)), 'Remove the parameter from the endpoint at the provider.');
            }
        }

        $separator = is_string($query) && $query !== '' ? '&' : (str_ends_with($endpoint, '?') ? '' : '?');

        return $endpoint.$separator.http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}

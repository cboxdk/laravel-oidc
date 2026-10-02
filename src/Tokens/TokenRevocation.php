<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Client\ClientAuthentication;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\InvalidArgument;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\RevocationRejected;
use Cbox\Oidc\Support\OAuthError;
use Cbox\Oidc\Support\StrictJson;
use JsonException;
use SensitiveParameter;

/**
 * Revokes a refresh or access token at the provider (RFC 7009), with the
 * connection's client authentication.
 *
 * - The endpoint must be advertised (revocation_endpoint), else
 *   {@see EndpointNotSupported}; ask {@see self::supported()} first.
 * - 200 means revoked, also for a token the provider did not know or had
 *   already invalidated (RFC 7009 2.2).
 * - An OAuth error is {@see RevocationRejected}; 503 and the other temporary
 *   failures are {@see ProviderUnavailable}, after which the request may be
 *   retried (RFC 7009 2.2.1).
 *
 * Revoking the refresh token usually ends the grant at the provider, the
 * access tokens issued from it included. Call it when the person logs out,
 * from a queued job if the logout should not wait for the provider.
 */
final readonly class TokenRevocation
{
    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private HttpClient $http,
        private ClientAuthentication $authentication,
    ) {}

    /**
     * Whether the connection's provider advertises a revocation endpoint.
     *
     * @throws OidcException when the configuration or discovery fails
     */
    public function supported(?string $connection = null): bool
    {
        return $this->metadata->for($this->config->connection($connection))->revocationEndpoint !== null;
    }

    /**
     * Revokes $token at the provider of $connection (the default when null).
     * $hint says which kind of token it is; null sends no hint.
     *
     * @throws InvalidArgument when the token is malformed
     * @throws EndpointNotSupported
     * @throws RevocationRejected
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     * @throws OidcException when the configuration or discovery fails
     */
    public function revoke(#[SensitiveParameter] string $token, ?TokenTypeHint $hint = TokenTypeHint::RefreshToken, ?string $connection = null): void
    {
        InvalidArgument::assertToken('$token', $token);

        $config = $this->config->connection($connection);
        $metadata = $this->metadata->for($config);
        $url = $metadata->revocationEndpoint
            ?? throw EndpointNotSupported::missing($config->name, 'revocation_endpoint', 'End the session locally; the provider ends the grant when the token expires. Check supported() before revoking.');

        $form = ['token' => $token];

        if ($hint instanceof TokenTypeHint) {
            $form['token_type_hint'] = $hint->value;
        }

        $response = $this->http->send($this->authentication->request($config, $metadata, $url, $form));

        if ($response->successful()) {
            return;
        }

        if ($response->temporaryFailure()) {
            throw ProviderUnavailable::status($url, $response->status);
        }

        try {
            $document = StrictJson::decodeObject($response->body);
        } catch (JsonException) {
            $document = null;
        }

        if ($response->status >= 400 && $response->status < 500 && is_array($document) && array_key_exists('error', $document)) {
            throw RevocationRejected::byProvider($config->name, $url, $response->status, OAuthError::code($document['error']));
        }

        throw InvalidProviderResponse::status($url, $response->status);
    }
}

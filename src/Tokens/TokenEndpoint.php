<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Client\ClientAuthentication;
use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Http\HttpResponse;
use Cbox\Oidc\Support\OAuthError;
use Cbox\Oidc\Support\StrictJson;
use JsonException;
use Psr\Clock\ClockInterface;
use SensitiveParameter;

/**
 * Talks to the provider's token endpoint (RFC 6749 4.1.3 and 5, OpenID
 * Connect Core 3.1.3), with the connection's client authentication.
 *
 * A token response must be a JSON object with a non-empty access_token and a
 * token_type of Bearer (in any case); a code exchange must also return an
 * id_token. An OAuth error answer is {@see TokenRequestRejected}, with its
 * error code only.
 */
final readonly class TokenEndpoint
{
    public function __construct(
        private HttpClient $http,
        private ClientAuthentication $authentication,
        private ClockInterface $clock,
    ) {}

    /**
     * Exchanges an authorization code (with its PKCE verifier) for tokens.
     *
     * @throws TokenRequestRejected
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     */
    public function exchangeCode(ConnectionConfig $connection, ProviderMetadata $metadata, #[SensitiveParameter] string $code, #[SensitiveParameter] string $codeVerifier, string $redirectUri): TokenSet
    {
        $tokens = $this->request($connection, $metadata, [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirectUri,
            'code_verifier' => $codeVerifier,
        ]);

        if ($tokens->idToken === null) {
            throw InvalidProviderResponse::malformed($metadata->tokenEndpoint, 'token response', 'it has no id_token, although the scope includes openid');
        }

        return $tokens;
    }

    /**
     * Sends one grant to the token endpoint and reads the token response.
     *
     * @param  array<string, string>  $form
     *
     * @throws TokenRequestRejected
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     */
    public function request(ConnectionConfig $connection, ProviderMetadata $metadata, #[SensitiveParameter] array $form): TokenSet
    {
        $url = $metadata->tokenEndpoint;
        $response = $this->http->send($this->authentication->request($connection, $metadata, $url, $form));

        if ($response->temporaryFailure()) {
            throw ProviderUnavailable::status($url, $response->status);
        }

        $document = $this->document($response);

        if (! $response->successful()) {
            if ($response->status >= 400 && $response->status < 500 && $document !== null && array_key_exists('error', $document)) {
                throw TokenRequestRejected::byProvider($connection->name, $url, $response->status, OAuthError::code($document['error']));
            }

            throw InvalidProviderResponse::status($url, $response->status);
        }

        if ($document === null) {
            throw InvalidProviderResponse::malformed($url, 'token response', 'it is not a JSON object with unique keys');
        }

        return $this->tokens($document, $url);
    }

    /**
     * @return array<array-key, mixed>|null
     */
    private function document(HttpResponse $response): ?array
    {
        try {
            return StrictJson::decodeObject($response->body);
        } catch (JsonException) {
            return null;
        }
    }

    /**
     * @param  array<array-key, mixed>  $document
     */
    private function tokens(array $document, string $url): TokenSet
    {
        $malformed = static fn (string $problem): InvalidProviderResponse => InvalidProviderResponse::malformed($url, 'token response', $problem);

        $accessToken = $document['access_token'] ?? null;

        if (! is_string($accessToken) || $accessToken === '') {
            throw $malformed('it has no access_token');
        }

        $tokenType = $document['token_type'] ?? null;

        if (! is_string($tokenType) || strcasecmp($tokenType, 'Bearer') !== 0) {
            throw $malformed(is_string($tokenType) ? 'its token_type is not Bearer, the only type the package supports' : 'it has no token_type');
        }

        $optional = static function (string $name) use ($document, $malformed): ?string {
            $value = $document[$name] ?? null;

            if ($value !== null && (! is_string($value) || $value === '')) {
                throw $malformed(sprintf('its %s is not a non-empty string', $name));
            }

            return $value;
        };

        $idToken = $optional('id_token');
        $refreshToken = $optional('refresh_token');
        $scope = $optional('scope');
        $expiresIn = $document['expires_in'] ?? null;

        // Some providers send expires_in as a string of digits.
        if (is_string($expiresIn) && ctype_digit($expiresIn) && strlen($expiresIn) <= 10) {
            $expiresIn = (int) $expiresIn;
        }

        if ($expiresIn !== null && (! is_int($expiresIn) || $expiresIn < 0)) {
            throw $malformed('its expires_in is not a whole number of seconds');
        }

        $now = $this->clock->now();

        return new TokenSet(
            accessToken: $accessToken,
            tokenType: 'Bearer',
            idToken: $idToken,
            refreshToken: $refreshToken,
            expiresIn: $expiresIn,
            expiresAt: $expiresIn === null ? null : $now->setTimestamp($now->getTimestamp() + $expiresIn),
            scopes: $scope === null ? null : array_values(array_filter(explode(' ', $scope), static fn (string $value): bool => $value !== '')),
        );
    }
}

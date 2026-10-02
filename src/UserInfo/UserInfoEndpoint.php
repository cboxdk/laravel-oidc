<?php

declare(strict_types=1);

namespace Cbox\Oidc\UserInfo;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\GroupsSource;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\HttpClient;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\EndpointNotSupported;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\UserInfoRejected;
use Cbox\Oidc\Http\HttpRequest;
use Cbox\Oidc\Support\OAuthError;
use Cbox\Oidc\Support\StrictJson;
use Cbox\Oidc\Tokens\VerifiedClaims;
use JsonException;
use SensitiveParameter;

/**
 * Calls the provider's userinfo endpoint (OpenID Connect Core 5.3) with an
 * access token and returns the person's claims:
 *
 * 1. the endpoint must be advertised (userinfo_endpoint), else
 *    {@see EndpointNotSupported};
 * 2. GET with the access token as a Bearer token (RFC 6750 2.1);
 * 3. 401 or 403 is {@see UserInfoRejected}, with the Bearer error code; 408,
 *    429 and 5xx are {@see ProviderUnavailable};
 * 4. the response must be a JSON object with unique keys. A signed or
 *    encrypted response (application/jwt) is refused: the package reads
 *    plain JSON userinfo only;
 * 5. its sub must equal the ID token's sub, else {@see UserInfoRejected}
 *    (OpenID Connect Core 5.3.4: the claims could belong to someone else);
 * 6. when the connection reads groups from userinfo, the groups claim must
 *    be a list of strings.
 */
final readonly class UserInfoEndpoint
{
    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private HttpClient $http,
    ) {}

    /**
     * Whether the connection's provider advertises a userinfo endpoint.
     *
     * @throws OidcException when the configuration or discovery fails
     */
    public function supported(?string $connection = null): bool
    {
        $config = $this->config->connection($connection);

        return $this->metadata->for($config)->userinfoEndpoint !== null;
    }

    /**
     * The userinfo claims of the person $claims identifies.
     *
     * @param  VerifiedClaims  $claims  the verified ID token claims of the login the access token belongs to
     *
     * @throws EndpointNotSupported
     * @throws UserInfoRejected
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     * @throws OidcException when the configuration or discovery fails
     */
    public function fetch(VerifiedClaims $claims, #[SensitiveParameter] string $accessToken): UserInfo
    {
        $config = $this->config->connection($claims->connection);
        $url = $this->metadata->for($config)->userinfoEndpoint
            ?? throw EndpointNotSupported::missing($config->name, 'userinfo_endpoint', sprintf('Read the claims from the ID token instead, and set oidc.connections.%s.groups.source to id_token or none.', $config->name));

        $response = $this->http->send(HttpRequest::get($url, ['Accept' => 'application/json', 'Authorization' => 'Bearer '.$accessToken]));

        if ($response->status === 401 || $response->status === 403) {
            throw UserInfoRejected::byProvider($config->name, $url, $response->status, $this->bearerError($response->header('WWW-Authenticate')));
        }

        if ($response->temporaryFailure()) {
            throw ProviderUnavailable::status($url, $response->status);
        }

        if (! $response->successful()) {
            throw InvalidProviderResponse::status($url, $response->status);
        }

        if (str_starts_with(strtolower(trim((string) $response->header('Content-Type'))), 'application/jwt')) {
            throw InvalidProviderResponse::malformed($url, 'userinfo response', 'it is a signed or encrypted JWT (application/jwt), which the package does not read; configure the client at the provider to return plain JSON userinfo');
        }

        try {
            $document = StrictJson::decodeObject($response->body);
        } catch (JsonException $exception) {
            throw InvalidProviderResponse::malformed($url, 'userinfo response', 'it is not a JSON object with unique keys', $exception);
        }

        if ($document !== [] && array_is_list($document)) {
            throw InvalidProviderResponse::malformed($url, 'userinfo response', 'it is not a JSON object');
        }

        /** @var array<string, mixed> $document */
        $subject = $document['sub'] ?? null;

        if (! is_string($subject) || ! hash_equals($claims->subject, $subject)) {
            throw UserInfoRejected::subjectMismatch($config->name);
        }

        return new UserInfo($config->name, $subject, $this->groups($config, $url, $document), $document);
    }

    /**
     * @param  array<string, mixed>  $document
     * @return list<string>|null
     */
    private function groups(ConnectionConfig $config, string $url, array $document): ?array
    {
        if ($config->groups->source !== GroupsSource::UserInfo) {
            return null;
        }

        $groups = $document[$config->groups->claim] ?? [];

        if (! is_array($groups) || ! array_is_list($groups) || array_filter($groups, is_string(...)) !== $groups) {
            throw InvalidProviderResponse::malformed($url, 'userinfo response', sprintf('its %s claim is not a list of strings', $config->groups->claim));
        }

        /** @var list<string> $groups */
        return array_values(array_unique($groups));
    }

    /**
     * The error code of a WWW-Authenticate: Bearer error="..." challenge.
     */
    private function bearerError(?string $challenge): ?string
    {
        if ($challenge === null || preg_match('/\berror\s*=\s*"?([^",\s]*)"?/i', $challenge, $match) !== 1) {
            return null;
        }

        return OAuthError::code($match[1]);
    }
}

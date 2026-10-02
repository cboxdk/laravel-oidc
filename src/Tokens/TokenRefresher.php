<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

use Cbox\Oidc\Config\GroupsSource;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Exceptions\InvalidArgument;
use Cbox\Oidc\Exceptions\InvalidProviderResponse;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\ProviderUnavailable;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use SensitiveParameter;

/**
 * Renews a login's tokens with its refresh token (RFC 6749 6, OpenID Connect
 * Core 12):
 *
 * 1. the refresh token goes to the token endpoint of the connection the
 *    original claims came from, with the connection's client authentication;
 * 2. a refused refresh is {@see TokenRequestRejected}; on invalid_grant
 *    ({@see TokenRequestRejected::refreshTokenInvalid()}) the session it kept
 *    alive is over;
 * 3. an ID token in the response is verified like the login's, without a
 *    nonce or max_age, and must belong to the same login: same issuer,
 *    subject and tenant, and the original auth_time and nonce when it
 *    carries them ({@see IdTokenExpectations::forRefresh()}).
 *
 * Request offline_access in the connection's scopes (or, for Google,
 * access_type=offline) to get a refresh token at login at all.
 */
final readonly class TokenRefresher
{
    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private TokenEndpoint $tokens,
        private IdTokenVerifier $idTokens,
    ) {}

    /**
     * @param  VerifiedClaims  $original  the claims of the login the refresh token belongs to
     * @param  list<string>|null  $scopes  narrows the new access token to these scopes; null keeps the original grant
     *
     * @throws InvalidArgument when the refresh token or a scope is malformed
     * @throws TokenRequestRejected when the provider refuses the refresh token
     * @throws TokenRejected when the new ID token fails verification or belongs to another login
     * @throws InvalidProviderResponse
     * @throws ProviderUnavailable
     * @throws OutboundRequestBlocked
     * @throws OidcException when the configuration or discovery fails
     */
    public function refresh(VerifiedClaims $original, #[SensitiveParameter] string $refreshToken, ?array $scopes = null): RefreshResult
    {
        InvalidArgument::assertToken('$refreshToken', $refreshToken);
        InvalidArgument::assertScopes('$scopes', $scopes ?? []);

        $config = $this->config->connection($original->connection);
        $metadata = $this->metadata->for($config);
        $tokens = $this->tokens->refresh($config, $metadata, $refreshToken, $scopes);
        $claims = $original;

        if ($tokens->idToken !== null) {
            $claims = $this->idTokens->verify($config, $tokens->idToken, IdTokenExpectations::forRefresh($original, $tokens->accessToken));

            // Groups read from userinfo are not in the ID token; keep the
            // last known ones until the application calls userinfo again.
            if ($config->groups->source === GroupsSource::UserInfo) {
                $claims = $claims->withGroups($original->groups, $original->groupsOverage);
            }
        }

        return new RefreshResult(
            tokens: $tokens,
            refreshToken: $tokens->refreshToken ?? $refreshToken,
            rotated: $tokens->refreshToken !== null && ! hash_equals($refreshToken, $tokens->refreshToken),
            claims: $claims,
            idTokenRenewed: $tokens->idToken !== null,
        );
    }
}

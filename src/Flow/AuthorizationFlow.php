<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Config\OidcConfig;
use Cbox\Oidc\Contracts\TransactionStore;
use Cbox\Oidc\Discovery\MetadataRepository;
use Cbox\Oidc\Discovery\ProviderMetadata;
use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\CallbackRejected;
use Cbox\Oidc\Exceptions\InvalidAuthorizationOptions;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\OutboundRequestBlocked;
use Cbox\Oidc\Exceptions\TenantRejected;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Support\Base64Url;
use Cbox\Oidc\Support\OAuthError;
use Cbox\Oidc\Tokens\IdTokenExpectations;
use Cbox\Oidc\Tokens\IdTokenVerifier;
use Cbox\Oidc\Tokens\TokenEndpoint;
use Cbox\Ssrf\Contracts\UrlGuard;
use Cbox\Ssrf\Exceptions\BlockedUrl;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Psr\Clock\ClockInterface;

/**
 * The authorization code flow with PKCE (OpenID Connect Core 3.1).
 *
 * {@see self::redirect()} starts a login: it makes a fresh state, nonce and
 * PKCE verifier, keeps them in the {@see TransactionStore}, and sends the
 * browser to the provider.
 *
 * {@see self::callback()} finishes it, in this order:
 *
 * 1. the state must match a login this session started for this connection,
 *    which is then used up, and the login must be younger than
 *    oidc.flow.transaction_ttl_seconds;
 * 2. the iss parameter must equal the pinned issuer when the callback has one
 *    or the provider announces it (RFC 9207);
 * 3. an error answer from the provider becomes {@see AuthorizationDenied};
 * 4. the code must be present and well formed;
 * 5. the code is exchanged, with the PKCE verifier and the connection's
 *    client authentication;
 * 6. the ID token is verified ({@see IdTokenVerifier}) against the login's
 *    nonce and max_age, the access token's at_hash and the callback's iss.
 *
 * Give each connection its own callback route, and pass the connection to
 * callback(): a response for one connection then never reaches another.
 */
final readonly class AuthorizationFlow
{
    public function __construct(
        private OidcConfig $config,
        private MetadataRepository $metadata,
        private TransactionStore $transactions,
        private TokenEndpoint $tokens,
        private IdTokenVerifier $idTokens,
        private UrlGuard $guard,
        private ClockInterface $clock,
    ) {}

    /**
     * Starts a login and returns where to send the browser.
     *
     * @throws InvalidAuthorizationOptions
     * @throws OidcException when the configuration or discovery fails
     */
    public function start(?string $connection = null, AuthorizationOptions $options = new AuthorizationOptions): AuthorizationRequest
    {
        $config = $this->config->connection($connection);
        $metadata = $this->metadata->for($config);

        $transaction = new AuthorizationTransaction(
            connection: $config->name,
            state: Base64Url::random(32),
            nonce: Base64Url::random(32),
            codeVerifier: Pkce::verifier(),
            redirectUri: $config->redirectUri,
            maxAge: $options->maxAge ?? $config->maxAge,
            createdAt: $this->clock->now()->getTimestamp(),
        );

        $url = AuthorizationUrl::build($config, $metadata, $transaction, $options);
        $this->assertSafeRedirect($url);
        $this->transactions->put($transaction);

        return new AuthorizationRequest($config->name, $url, $transaction->state);
    }

    /**
     * Starts a login and answers with the redirect to the provider.
     *
     * @throws InvalidAuthorizationOptions
     * @throws OidcException when the configuration or discovery fails
     */
    public function redirect(?string $connection = null, AuthorizationOptions $options = new AuthorizationOptions): RedirectResponse
    {
        return $this->start($connection, $options)->redirect();
    }

    /**
     * Checks the callback of a login, exchanges its code for tokens and
     * verifies the ID token.
     *
     * @throws CallbackRejected when the callback fails a check before the token request
     * @throws AuthorizationDenied when the provider answered with an error
     * @throws TokenRejected when the ID token fails verification ({@see TenantRejected} for a tenant that is not allowed)
     * @throws OidcException when the token request fails
     */
    public function callback(Request $request, ?string $connection = null): CallbackResult
    {
        $config = $this->config->connection($connection);
        $parameters = CallbackParameters::fromRequest($request, $config->name);
        $transaction = $this->transaction($config, $parameters);
        $metadata = $this->metadata->for($config);

        $this->assertIssuer($config, $metadata, $parameters->iss);

        if ($parameters->error !== null) {
            throw AuthorizationDenied::byProvider($config->name, OAuthError::code($parameters->error));
        }

        $code = $parameters->code;

        if ($code === null) {
            throw CallbackRejected::invalid($config->name, 'has neither a code nor an error');
        }

        // RFC 6749 A.11: VSCHAR. A code with other bytes is not one, and is
        // never sent on to the provider.
        if (preg_match('/^[\x20-\x7E]{1,2048}$/D', $code) !== 1) {
            throw CallbackRejected::invalid($config->name, 'has a code that is not 1 to 2048 printable ASCII characters');
        }

        $tokens = $this->tokens->exchangeCode($config, $metadata, $code, $transaction->codeVerifier, $transaction->redirectUri);
        $claims = $this->idTokens->verify($config, (string) $tokens->idToken, IdTokenExpectations::forLogin($transaction, $tokens->accessToken, $parameters->iss));

        return new CallbackResult($config->name, $claims, $tokens, $transaction, $parameters->iss);
    }

    private function transaction(ConnectionConfig $config, CallbackParameters $parameters): AuthorizationTransaction
    {
        if ($parameters->state === null || $parameters->state === '') {
            throw CallbackRejected::stateMismatch($config->name, 'it has no state parameter');
        }

        if (strlen($parameters->state) > 512) {
            throw CallbackRejected::stateMismatch($config->name, 'its state is longer than any state the package makes');
        }

        $transaction = $this->transactions->pull($parameters->state);

        if (! $transaction instanceof AuthorizationTransaction) {
            throw CallbackRejected::stateMismatch($config->name, 'no login of this session matches its state');
        }

        if ($transaction->connection !== $config->name) {
            throw CallbackRejected::stateMismatch($config->name, sprintf('its state belongs to a login of connection "%s"', $transaction->connection));
        }

        $age = $this->clock->now()->getTimestamp() - $transaction->createdAt;
        $ttl = $this->config->flow->transactionTtlSeconds;

        if ($age > $ttl) {
            throw CallbackRejected::expired($config->name, $age, $ttl);
        }

        return $transaction;
    }

    /**
     * RFC 9207 2.4: when the callback carries iss, or the provider says it
     * always does, iss must be the pinned issuer. For an issuer template
     * ({tenantid}), iss must be the template with one tenant filled in; the
     * tenant is checked against the ID token later.
     */
    private function assertIssuer(ConnectionConfig $config, ProviderMetadata $metadata, ?string $iss): void
    {
        if ($iss === null) {
            if ($metadata->authorizationResponseIssParameterSupported) {
                throw CallbackRejected::issuerMismatch($config->name, $config->issuer, null);
            }

            return;
        }

        $matches = $config->hasTenantTemplate()
            ? preg_match('/^'.str_replace(preg_quote(ConnectionConfig::TENANT_TEMPLATE, '/'), '[A-Za-z0-9-]{1,64}', preg_quote($config->issuer, '/')).'$/D', $iss) === 1
            : $iss === $config->issuer;

        if (! $matches) {
            throw CallbackRejected::issuerMismatch($config->name, $config->issuer, $iss);
        }
    }

    private function assertSafeRedirect(string $url): void
    {
        try {
            $this->guard->assertSafeRedirect($url, ['https']);
        } catch (BlockedUrl $exception) {
            throw OutboundRequestBlocked::redirect($url, $exception);
        }
    }
}

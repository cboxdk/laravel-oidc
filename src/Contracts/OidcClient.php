<?php

declare(strict_types=1);

namespace Cbox\Oidc\Contracts;

use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\CallbackRejected;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Facades\Oidc;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationRequest;
use Cbox\Oidc\Flow\CallbackResult;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\OidcConnection;
use Cbox\Oidc\Tokens\RefreshResult;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Cbox\Oidc\UserInfo\UserInfo;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use SensitiveParameter;

/**
 * Everything an application does with its OpenID providers, in one place:
 * what the {@see Oidc} facade calls, and what to type-hint in a controller.
 *
 * Every method takes the connection by name; null is the default connection
 * (oidc.default). {@see self::connection()} gives the same calls bound to one
 * connection. Oidc::fake() swaps this binding for an in-memory fake, so code
 * that uses the facade or this contract is faked in tests.
 */
interface OidcClient
{
    /**
     * The calls of this client, bound to one connection.
     *
     * @throws OidcException when the connection is not configured
     */
    public function connection(?string $name = null): OidcConnection;

    /**
     * Starts a login: a fresh state, nonce and PKCE verifier, kept in the
     * session, and the URL to send the browser to. Return it from a route.
     *
     * @throws OidcException when the options, the configuration or discovery fail
     */
    public function start(?string $connection = null, ?AuthorizationOptions $options = null): AuthorizationRequest;

    /**
     * Starts a login and answers with the redirect to the provider.
     *
     * @throws OidcException when the options, the configuration or discovery fail
     */
    public function redirect(?string $connection = null, ?AuthorizationOptions $options = null): RedirectResponse;

    /**
     * Checks the browser's return from the provider, exchanges the code and
     * verifies the ID token. $request defaults to the current request.
     *
     * @throws CallbackRejected when the callback fails a check before the token request
     * @throws AuthorizationDenied when the provider answered with an error
     * @throws TokenRejected when the ID token fails verification
     * @throws OidcException when the token request or userinfo fails
     */
    public function callback(?string $connection = null, ?Request $request = null): CallbackResult;

    /**
     * Renews the tokens of the login $claims came from.
     *
     * @param  list<string>|null  $scopes  narrows the new access token; null keeps the original grant
     *
     * @throws TokenRequestRejected when the provider refuses the refresh token
     * @throws OidcException when the new ID token fails verification, or the call fails
     */
    public function refresh(VerifiedClaims $claims, #[SensitiveParameter] string $refreshToken, ?array $scopes = null): RefreshResult;

    /**
     * The userinfo claims of the person $claims names, read with their
     * access token; the response must name the same subject.
     *
     * @throws OidcException when the provider has no userinfo endpoint, or the call fails
     */
    public function userInfo(VerifiedClaims $claims, #[SensitiveParameter] string $accessToken): UserInfo;

    /**
     * RP-initiated logout: the redirect to the provider's end_session_endpoint,
     * or to $fallback when the provider has none. End your own session first.
     *
     * @throws OidcException when the configuration or discovery fails
     */
    public function logout(?string $connection = null, ?LogoutOptions $options = null, string $fallback = '/'): RedirectResponse;

    /**
     * Revokes a refresh or access token at the provider (RFC 7009).
     *
     * @throws OidcException when the provider has no revocation endpoint, refuses the request, or the call fails
     */
    public function revoke(#[SensitiveParameter] string $token, ?TokenTypeHint $hint = TokenTypeHint::RefreshToken, ?string $connection = null): void;
}

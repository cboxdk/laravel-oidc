<?php

declare(strict_types=1);

namespace Cbox\Oidc\Testing;

use Cbox\Oidc\Contracts\OidcClient;
use Cbox\Oidc\Events\BackChannelLogoutReceived;
use Cbox\Oidc\Exceptions\AuthorizationDenied;
use Cbox\Oidc\Exceptions\InvalidArgument;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\TokenRequestRejected;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Flow\AuthorizationOptions;
use Cbox\Oidc\Flow\AuthorizationRequest;
use Cbox\Oidc\Flow\AuthorizationTransaction;
use Cbox\Oidc\Flow\CallbackResult;
use Cbox\Oidc\Flow\Prompt;
use Cbox\Oidc\Logout\LogoutOptions;
use Cbox\Oidc\Logout\LogoutToken;
use Cbox\Oidc\OidcConnection;
use Cbox\Oidc\Support\Base64Url;
use Cbox\Oidc\Support\OAuthError;
use Cbox\Oidc\Tokens\RefreshResult;
use Cbox\Oidc\Tokens\TokenSet;
use Cbox\Oidc\Tokens\TokenTypeHint;
use Cbox\Oidc\Tokens\VerifiedClaims;
use Cbox\Oidc\UserInfo\UserInfo;
use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use LogicException;
use PHPUnit\Framework\Assert;
use Psr\Clock\ClockInterface;
use SensitiveParameter;

/**
 * An in-memory {@see OidcClient} for your application's tests: no provider,
 * no HTTP, no keys.
 *
 *     $oidc = Oidc::fake();
 *     $oidc->signIn('user-1', ['email' => 'ada@example.com', 'groups' => ['staff']]);
 *
 *     $this->get('/login')->assertRedirect();
 *     $this->get('/oidc/callback')->assertRedirect('/dashboard');
 *
 *     $oidc->assertSignedIn('user-1');
 *
 * Each callback takes the next outcome queued for its connection with
 * {@see self::signIn()}, {@see self::denySignIn()} or {@see self::failSignIn()};
 * a callback with nothing queued throws a LogicException that says so. The
 * fake does not check the callback's state or code, so a test can call the
 * callback route directly.
 *
 * The claims, tokens and results have the same types and shapes as the real
 * ones. The tokens are not signed: an ID token is an unsecured JWT (alg none)
 * that no verifier accepts, so it can never pass for a real one.
 *
 * Connections are the ones config/oidc.php names, read without the checks of
 * the real configuration, so a test needs no issuer or secret. With no
 * connections configured, any name is accepted.
 *
 * In assertions, a null connection means any connection.
 */
final class OidcFake implements OidcClient
{
    /** The issuer of a connection without a configured issuer. */
    public const string ISSUER = 'https://oidc.fake.test';

    /** Where {@see self::start()} sends the browser. Nothing answers it. */
    public const string AUTHORIZATION_URL = 'https://oidc.fake.test/authorize';

    /** The tid filled into an Entra {tenantid} issuer when the claims name none. */
    public const string TENANT_ID = '00000000-0000-0000-0000-00000000f4ce';

    /** @var array<string, list<array{subject: string, claims: array<string, mixed>}|OidcException>> */
    private array $outcomes = [];

    /** @var array<string, list<OidcException>> */
    private array $refreshFailures = [];

    /** @var array<string, array<string, mixed>> */
    private array $userInfoClaims = [];

    /** @var array<string, list<AuthorizationTransaction>> started logins whose callback has not run */
    private array $pending = [];

    /** @var list<array{connection: string, options: AuthorizationOptions, request: AuthorizationRequest}> */
    private array $starts = [];

    /** @var list<CallbackResult> */
    private array $signIns = [];

    /** @var list<array{connection: string, result: RefreshResult}> */
    private array $refreshes = [];

    /** @var list<array{connection: string, options: LogoutOptions, target: string}> */
    private array $logouts = [];

    /** @var list<array{connection: string, token: string, hint: TokenTypeHint|null}> */
    private array $revocations = [];

    /** @var array<string, true> refresh tokens revoked, or used up by a refresh */
    private array $deadTokens = [];

    private int $sequence = 0;

    public function __construct(
        private readonly Repository $config,
        private readonly ClockInterface $clock,
        private readonly Container $container,
    ) {}

    /**
     * Queues a successful sign-in: the next callback of the connection returns
     * these claims. $claims replace the defaults (iss, sub, aud, iat, exp,
     * auth_time, nonce, sid); a null claim is left out. Put groups under the
     * connection's groups claim (groups by default), and the tenant under its
     * tenant claim (tid, hd).
     *
     * @param  array<string, mixed>  $claims
     */
    public function signIn(string $subject = 'user-1', array $claims = [], ?string $connection = null): self
    {
        if ($subject === '') {
            throw InvalidArgument::because('$subject', 'is empty', 'Pass the subject the provider would send, such as user-1.');
        }

        $this->outcomes[$this->name($connection)][] = ['subject' => $subject, 'claims' => $claims];

        return $this;
    }

    /**
     * Queues a sign-in the provider answers with an OAuth error, such as
     * access_denied (the person cancelled) or login_required (a silent
     * login that needs the person): the next callback throws
     * {@see AuthorizationDenied}.
     */
    public function denySignIn(string $error = 'access_denied', ?string $connection = null): self
    {
        $name = $this->name($connection);

        return $this->failSignIn(AuthorizationDenied::byProvider($name, OAuthError::code($error)), $name);
    }

    /**
     * Queues a sign-in that fails with $exception, such as
     * TenantRejected::notAllowed(...) or CallbackRejected::stateMismatch(...).
     */
    public function failSignIn(OidcException $exception, ?string $connection = null): self
    {
        $this->outcomes[$this->name($connection)][] = $exception;

        return $this;
    }

    /**
     * Makes the next refresh of the connection fail with $exception, such as
     * TokenRequestRejected::byProvider($connection, $url, 400, 'invalid_grant', 'refresh_token').
     * A refresh token that was revoked, or used up by an earlier refresh,
     * fails that way without this.
     */
    public function failRefresh(OidcException $exception, ?string $connection = null): self
    {
        $this->refreshFailures[$this->name($connection)][] = $exception;

        return $this;
    }

    /**
     * Claims userinfo returns for the connection, on top of the profile
     * claims of the sign-in.
     *
     * @param  array<string, mixed>  $claims
     */
    public function withUserInfo(array $claims, ?string $connection = null): self
    {
        $this->userInfoClaims[$this->name($connection)] = $claims;

        return $this;
    }

    /**
     * Dispatches {@see BackChannelLogoutReceived}, as the back-channel logout
     * route does for a verified logout token, so your listener runs. Name the
     * subject, the session (sid) or both.
     */
    public function backChannelLogout(?string $subject = 'user-1', ?string $sessionId = null, ?string $connection = null): LogoutToken
    {
        if ($subject === null && $sessionId === null) {
            throw InvalidArgument::because('$subject and $sessionId', 'are both null', 'A logout token names the subject, the session (sid) or both; pass at least one.');
        }

        $name = $this->name($connection);
        $now = $this->now();
        $claims = array_filter([
            'iss' => $this->issuer($name, []),
            'aud' => $this->clientId($name),
            'iat' => $now->getTimestamp(),
            'exp' => $now->getTimestamp() + 120,
            'jti' => 'fake-jti-'.(++$this->sequence),
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => []],
            'sub' => $subject,
            'sid' => $sessionId,
        ], static fn (mixed $value): bool => $value !== null);

        $token = new LogoutToken($name, (string) $claims['iss'], $subject, $sessionId, (string) $claims['jti'], $now, $now->modify('+120 seconds'), $claims);
        // Resolved now, not when the fake was made, so Event::fake() in the
        // same test sees the event.
        $this->container->make(Dispatcher::class)->dispatch(new BackChannelLogoutReceived($token));

        return $token;
    }

    public function connection(?string $name = null): OidcConnection
    {
        return new OidcConnection($this, $this->name($name));
    }

    public function start(?string $connection = null, ?AuthorizationOptions $options = null): AuthorizationRequest
    {
        $name = $this->name($connection);
        $options ??= new AuthorizationOptions;
        $transaction = $this->transaction($name);
        $this->pending[$name][] = $transaction;

        $query = array_filter([
            'connection' => $name,
            'client_id' => $this->clientId($name),
            'redirect_uri' => $transaction->redirectUri,
            'scope' => implode(' ', array_values(array_unique([...$this->scopes($name), ...$options->scopes]))),
            'state' => $transaction->state,
            'login_hint' => $options->loginHint,
            'prompt' => $options->prompts === [] ? null : implode(' ', array_map(static fn (Prompt $prompt): string => $prompt->value, $options->prompts)),
        ], static fn (?string $value): bool => $value !== null);

        $request = new AuthorizationRequest($name, self::AUTHORIZATION_URL.'?'.http_build_query($query, '', '&', PHP_QUERY_RFC3986), $transaction->state);
        $this->starts[] = ['connection' => $name, 'options' => $options, 'request' => $request];

        return $request;
    }

    public function redirect(?string $connection = null, ?AuthorizationOptions $options = null): RedirectResponse
    {
        return $this->start($connection, $options)->redirect();
    }

    public function callback(?string $connection = null, ?Request $request = null): CallbackResult
    {
        $name = $this->name($connection);
        $this->outcomes[$name] ??= [];
        $this->pending[$name] ??= [];
        $outcome = array_shift($this->outcomes[$name]);

        if ($outcome === null) {
            throw new LogicException(sprintf('Oidc::fake() has no sign-in queued for connection "%s". Call signIn(), denySignIn() or failSignIn() on the fake before the callback runs.', $name));
        }

        $transaction = array_pop($this->pending[$name]) ?? $this->transaction($name);

        if ($outcome instanceof OidcException) {
            throw $outcome;
        }

        $now = $this->now();
        $claims = $this->claims($name, $outcome['subject'], array_replace([
            'auth_time' => $now->getTimestamp(),
            'nonce' => $transaction->nonce,
            'sid' => 'fake-session-'.(++$this->sequence),
        ], $outcome['claims']));

        $userInfo = null;

        if ($this->groupsSource($name) === 'userinfo') {
            $userInfo = $this->userInfoFor($claims);
            $claims = $claims->withGroups($userInfo->groups);
        }

        $result = new CallbackResult($name, $claims, $this->tokens($name, $claims), $transaction, null, $userInfo);
        $this->signIns[] = $result;

        return $result;
    }

    /**
     * @param  list<string>|null  $scopes
     */
    public function refresh(VerifiedClaims $claims, #[SensitiveParameter] string $refreshToken, ?array $scopes = null): RefreshResult
    {
        InvalidArgument::assertToken('$refreshToken', $refreshToken);
        InvalidArgument::assertScopes('$scopes', $scopes ?? []);

        $name = $claims->connection;

        if (isset($this->deadTokens[$refreshToken])) {
            throw TokenRequestRejected::byProvider($name, self::ISSUER.'/token', 400, 'invalid_grant', 'refresh_token');
        }

        $this->refreshFailures[$name] ??= [];
        $failure = array_shift($this->refreshFailures[$name]);

        if ($failure !== null) {
            throw $failure;
        }

        // Rotation: the old refresh token is used up.
        $this->deadTokens[$refreshToken] = true;

        $now = $this->now();
        $renewed = $this->claims($name, $claims->subject, array_replace($claims->claims, [
            'iat' => $now->getTimestamp(),
            'exp' => $now->getTimestamp() + 3600,
        ]))->withGroups($claims->groups, $claims->groupsOverage);

        $tokens = $this->tokens($name, $renewed, $scopes);
        $result = new RefreshResult($tokens, (string) $tokens->refreshToken, true, $renewed, true);
        $this->refreshes[] = ['connection' => $name, 'result' => $result];

        return $result;
    }

    public function userInfo(VerifiedClaims $claims, #[SensitiveParameter] string $accessToken): UserInfo
    {
        InvalidArgument::assertToken('$accessToken', $accessToken);

        return $this->userInfoFor($claims);
    }

    public function logout(?string $connection = null, ?LogoutOptions $options = null, string $fallback = '/'): RedirectResponse
    {
        $name = $this->name($connection);
        $options ??= new LogoutOptions;
        $configured = $this->config->get(sprintf('oidc.connections.%s.post_logout_redirect_uri', $name));
        $target = $options->postLogoutRedirectUri ?? (is_string($configured) && $configured !== '' ? $configured : $fallback);

        $this->logouts[] = ['connection' => $name, 'options' => $options, 'target' => $target];

        // The provider's round trip is skipped: the browser goes straight to
        // where the provider would send it back.
        return new RedirectResponse($target);
    }

    public function revoke(#[SensitiveParameter] string $token, ?TokenTypeHint $hint = TokenTypeHint::RefreshToken, ?string $connection = null): void
    {
        InvalidArgument::assertToken('$token', $token);

        $this->revocations[] = ['connection' => $this->name($connection), 'token' => $token, 'hint' => $hint];
        $this->deadTokens[$token] = true;
    }

    /**
     * The sign-ins that succeeded, oldest first.
     *
     * @return list<CallbackResult>
     */
    public function signIns(?string $connection = null): array
    {
        return array_values(array_filter($this->signIns, static fn (CallbackResult $result): bool => $connection === null || $result->connection === $connection));
    }

    /**
     * Asserts that a login was started, and, with $callback, that one passes it.
     *
     * @param  (Closure(AuthorizationOptions, AuthorizationRequest): bool)|null  $callback
     */
    public function assertRedirected(?string $connection = null, ?Closure $callback = null): void
    {
        $matching = array_filter(
            $this->starts,
            static fn (array $start): bool => ($connection === null || $start['connection'] === $connection)
                && (! $callback instanceof Closure || $callback($start['options'], $start['request'])),
        );

        Assert::assertNotEmpty($matching, sprintf('No login %s was started%s.', $this->describe($connection), $callback instanceof Closure ? ' that matches the callback' : ''));
    }

    public function assertNotRedirected(?string $connection = null): void
    {
        $started = array_filter($this->starts, static fn (array $start): bool => $connection === null || $start['connection'] === $connection);

        Assert::assertEmpty($started, sprintf('%d login(s) %s were started.', count($started), $this->describe($connection)));
    }

    /**
     * Asserts that a callback succeeded, for $subject when given.
     */
    public function assertSignedIn(?string $subject = null, ?string $connection = null): void
    {
        $matching = array_filter(
            $this->signIns($connection),
            static fn (CallbackResult $result): bool => $subject === null || $result->claims->subject === $subject,
        );

        Assert::assertNotEmpty($matching, sprintf('Nobody%s signed in %s.', $subject === null ? '' : sprintf(' with subject "%s"', $subject), $this->describe($connection)));
    }

    public function assertNotSignedIn(?string $connection = null): void
    {
        $signIns = $this->signIns($connection);

        Assert::assertEmpty($signIns, sprintf('%d sign-in(s) %s succeeded.', count($signIns), $this->describe($connection)));
    }

    /**
     * Asserts that every queued sign-in was used by a callback.
     */
    public function assertNoPendingSignIns(): void
    {
        $left = array_sum(array_map(count(...), $this->outcomes));

        Assert::assertSame(0, $left, sprintf('%d queued sign-in(s) were never used by a callback.', $left));
    }

    public function assertRefreshed(?string $connection = null): void
    {
        Assert::assertNotEmpty($this->recorded($this->refreshes, $connection), sprintf('No tokens %s were refreshed.', $this->describe($connection)));
    }

    public function assertNotRefreshed(?string $connection = null): void
    {
        $refreshes = $this->recorded($this->refreshes, $connection);

        Assert::assertEmpty($refreshes, sprintf('%d refresh(es) %s happened.', count($refreshes), $this->describe($connection)));
    }

    /**
     * Asserts an RP-initiated logout, and, with $callback, one that passes it.
     *
     * @param  (Closure(LogoutOptions): bool)|null  $callback
     */
    public function assertLoggedOut(?string $connection = null, ?Closure $callback = null): void
    {
        $matching = array_filter(
            $this->recorded($this->logouts, $connection),
            static fn (array $logout): bool => ! $callback instanceof Closure || $callback($logout['options']),
        );

        Assert::assertNotEmpty($matching, sprintf('No logout %s happened%s.', $this->describe($connection), $callback instanceof Closure ? ' that matches the callback' : ''));
    }

    public function assertNotLoggedOut(?string $connection = null): void
    {
        $logouts = $this->recorded($this->logouts, $connection);

        Assert::assertEmpty($logouts, sprintf('%d logout(s) %s happened.', count($logouts), $this->describe($connection)));
    }

    /**
     * Asserts that a token was revoked: $token when given, else any.
     */
    public function assertRevoked(#[SensitiveParameter] ?string $token = null, ?string $connection = null): void
    {
        $matching = array_filter(
            $this->recorded($this->revocations, $connection),
            static fn (array $revocation): bool => $token === null || hash_equals($revocation['token'], $token),
        );

        Assert::assertNotEmpty($matching, sprintf('No %s %s was revoked.', $token === null ? 'token' : 'such token', $this->describe($connection)));
    }

    public function assertNotRevoked(?string $connection = null): void
    {
        $revocations = $this->recorded($this->revocations, $connection);

        Assert::assertEmpty($revocations, sprintf('%d token(s) %s were revoked.', count($revocations), $this->describe($connection)));
    }

    /**
     * @template T of array{connection: string}
     *
     * @param  list<T>  $records
     * @return list<T>
     */
    private function recorded(array $records, ?string $connection): array
    {
        return array_values(array_filter($records, static fn (array $record): bool => $connection === null || $record['connection'] === $connection));
    }

    private function describe(?string $connection): string
    {
        return $connection === null ? 'on any connection' : sprintf('on connection "%s"', $connection);
    }

    /**
     * The connection's name: null is oidc.default, and a name must be one of
     * oidc.connections when any are configured.
     */
    private function name(?string $connection): string
    {
        $default = $this->config->get('oidc.default');
        $name = $connection ?? (is_string($default) && $default !== '' ? $default : 'main');
        $connections = $this->config->get('oidc.connections');
        $known = is_array($connections) ? array_map(strval(...), array_keys($connections)) : [];

        if ($known !== [] && ! in_array($name, $known, true)) {
            throw UnknownConnection::named($name, $known);
        }

        return $name;
    }

    private function setting(string $connection, string $key): mixed
    {
        return $this->config->get(sprintf('oidc.connections.%s.%s', $connection, $key));
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function issuer(string $connection, array $claims): string
    {
        $configured = $this->setting($connection, 'issuer');
        $issuer = is_string($configured) && $configured !== '' ? $configured : self::ISSUER;
        $tenant = is_string($claims['tid'] ?? null) ? $claims['tid'] : self::TENANT_ID;

        return str_replace('{tenantid}', $tenant, $issuer);
    }

    private function clientId(string $connection): string
    {
        $configured = $this->setting($connection, 'client_id');

        return is_string($configured) && $configured !== '' ? $configured : 'fake-client';
    }

    /**
     * @return list<string>
     */
    private function scopes(string $connection): array
    {
        $configured = $this->setting($connection, 'scopes');

        return is_array($configured)
            ? array_values(array_filter($configured, is_string(...)))
            : ['openid', 'profile', 'email'];
    }

    private function groupsSource(string $connection): string
    {
        $source = $this->setting($connection, 'groups.source');

        return is_string($source) ? $source : 'id_token';
    }

    private function groupsClaim(string $connection): string
    {
        $claim = $this->setting($connection, 'groups.claim');

        return is_string($claim) && $claim !== '' ? $claim : 'groups';
    }

    private function tenantClaim(string $connection): ?string
    {
        $claim = $this->setting($connection, 'tenant.claim');

        return is_string($claim) && $claim !== '' ? $claim : null;
    }

    private function transaction(string $connection): AuthorizationTransaction
    {
        $redirect = $this->setting($connection, 'redirect_uri');

        return new AuthorizationTransaction(
            connection: $connection,
            state: Base64Url::random(32),
            nonce: Base64Url::random(32),
            codeVerifier: Base64Url::random(32),
            redirectUri: is_string($redirect) && $redirect !== '' ? $redirect : 'http://localhost/oidc/callback',
            maxAge: null,
            createdAt: $this->now()->getTimestamp(),
        );
    }

    /**
     * Verified claims as the real verifier returns them.
     *
     * @param  array<string, mixed>  $overrides
     */
    private function claims(string $connection, string $subject, array $overrides): VerifiedClaims
    {
        $now = $this->now()->getTimestamp();
        $claims = array_filter(array_replace([
            'iss' => $this->issuer($connection, $overrides),
            'sub' => $subject,
            'aud' => $this->clientId($connection),
            'iat' => $now,
            'exp' => $now + 3600,
        ], $overrides), static fn (mixed $value): bool => $value !== null);

        $audience = is_array($claims['aud'] ?? null) ? array_values(array_filter($claims['aud'], is_string(...))) : [(string) $this->claimString($claims, 'aud')];
        $groups = null;

        if ($this->groupsSource($connection) === 'id_token') {
            $groups = $this->stringList($claims[$this->groupsClaim($connection)] ?? null);
        }

        $tenantClaim = $this->tenantClaim($connection);

        return new VerifiedClaims(
            connection: $connection,
            issuer: (string) $this->claimString($claims, 'iss'),
            subject: (string) $this->claimString($claims, 'sub'),
            audience: $audience === [] ? [$this->clientId($connection)] : $audience,
            authorizedParty: $this->claimString($claims, 'azp'),
            issuedAt: $this->time($claims['iat'] ?? null) ?? $this->now(),
            expiresAt: $this->time($claims['exp'] ?? null) ?? $this->now()->modify('+3600 seconds'),
            authTime: $this->time($claims['auth_time'] ?? null),
            authenticationMethods: $this->stringList($claims['amr'] ?? null),
            authenticationContext: $this->claimString($claims, 'acr'),
            sessionId: $this->claimString($claims, 'sid'),
            tenant: $tenantClaim === null ? null : $this->claimString($claims, $tenantClaim),
            groups: $groups,
            groupsOverage: false,
            claims: $claims,
        );
    }

    private function userInfoFor(VerifiedClaims $claims): UserInfo
    {
        $protocol = ['iss', 'aud', 'azp', 'iat', 'exp', 'nbf', 'auth_time', 'nonce', 'sid', 'at_hash', 'c_hash', 'amr', 'acr', 'jti'];
        $values = array_replace(
            array_diff_key($claims->claims, array_flip($protocol)),
            $this->userInfoClaims[$claims->connection] ?? [],
            ['sub' => $claims->subject],
        );

        $groups = $this->groupsSource($claims->connection) === 'userinfo'
            ? $this->stringList($values[$this->groupsClaim($claims->connection)] ?? null)
            : null;

        return new UserInfo($claims->connection, $claims->subject, $groups, $values);
    }

    /**
     * @param  list<string>|null  $scopes
     */
    private function tokens(string $connection, VerifiedClaims $claims, ?array $scopes = null): TokenSet
    {
        $sequence = ++$this->sequence;

        return new TokenSet(
            accessToken: 'fake-access-token-'.$sequence,
            tokenType: 'Bearer',
            idToken: $this->unsecuredJwt($claims->claims),
            refreshToken: 'fake-refresh-token-'.$sequence,
            expiresIn: 3600,
            expiresAt: $this->now()->modify('+3600 seconds'),
            scopes: $scopes ?? $this->scopes($connection),
        );
    }

    /**
     * An unsecured JWT (RFC 7519 6, alg none): the shape of an ID token, which
     * no verifier accepts.
     *
     * @param  array<string, mixed>  $claims
     */
    private function unsecuredJwt(array $claims): string
    {
        return Base64Url::encode(json_encode(['alg' => 'none', 'typ' => 'JWT'], JSON_THROW_ON_ERROR))
            .'.'.Base64Url::encode(json_encode($claims, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES))
            .'.';
    }

    /**
     * @param  array<string, mixed>  $claims
     */
    private function claimString(array $claims, string $name): ?string
    {
        $value = $claims[$name] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @return list<string>|null
     */
    private function stringList(mixed $value): ?array
    {
        if (! is_array($value) || ! array_is_list($value)) {
            return null;
        }

        return array_values(array_unique(array_values(array_filter($value, is_string(...)))));
    }

    private function time(mixed $value): ?DateTimeImmutable
    {
        return is_int($value) ? new DateTimeImmutable('@'.$value) : null;
    }

    private function now(): DateTimeImmutable
    {
        return DateTimeImmutable::createFromInterface($this->clock->now())->setTimezone(new DateTimeZone('UTC'));
    }
}

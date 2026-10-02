<?php

declare(strict_types=1);

namespace Cbox\Oidc\Routing;

use Cbox\Oidc\Events\BackChannelLogoutReceived;
use Cbox\Oidc\Exceptions\OidcException;
use Cbox\Oidc\Exceptions\SigningKeyNotFound;
use Cbox\Oidc\Exceptions\SigningKeyUnsuitable;
use Cbox\Oidc\Exceptions\TokenRejected;
use Cbox\Oidc\Exceptions\UnknownConnection;
use Cbox\Oidc\Logout\LogoutTokenReplayGuard;
use Cbox\Oidc\Logout\LogoutTokenVerifier;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Psr\Log\LoggerInterface;
use Throwable;

/**
 * The back-channel logout endpoint (OpenID Connect Back-Channel Logout 1.0,
 * 2.5 and 2.8). Register it with the route macro:
 *
 * ```php
 * Route::oidcBackChannelLogout('oidc/{connection}/backchannel-logout');
 * ```
 *
 * It reads logout_token from the form body of a POST, verifies it
 * ({@see LogoutTokenVerifier}) and dispatches {@see BackChannelLogoutReceived}.
 * It answers:
 *
 * - 200 when the token verified and every listener returned;
 * - 400 with an OAuth error body when the token is missing or refused, also
 *   when it names a key the provider's key set does not have or that may not
 *   verify it (the refusal is logged as a warning with its code);
 * - 404 for a connection that is not configured;
 * - 503 when the provider's keys or discovery document cannot be loaded, so
 *   the provider may retry (logged as an error), and, logged as a warning,
 *   when the token names an unknown key while a refetch of the key set is
 *   held back by the cooldown (a rotation the next delivery may see).
 *
 * The endpoint takes requests from anyone, so a token that names an unknown
 * or unfit key is never logged as an error.
 *
 * Every answer carries Cache-Control: no-store. A listener that throws gives
 * the token's jti back, so a retry of the delivery is not taken for a replay.
 */
final readonly class BackChannelLogoutController
{
    public const string ROUTE_NAME = 'oidc.backchannel-logout';

    public function __construct(
        private LogoutTokenVerifier $verifier,
        private LogoutTokenReplayGuard $replays,
        private Dispatcher $events,
        private LoggerInterface $log,
    ) {}

    public function __invoke(Request $request, ?string $connection = null): Response|JsonResponse
    {
        $connection = $this->connection($request, $connection);
        // The form body only (2.5): a token in the query string is not read.
        // all() rather than get(), which throws on a list value.
        $logoutToken = $request->request->all()['logout_token'] ?? null;

        if (! is_string($logoutToken) || $logoutToken === '') {
            return $this->error(400, 'invalid_request', 'The request has no logout_token in its form body.');
        }

        try {
            $token = $this->verifier->verify($connection, $logoutToken);
        } catch (UnknownConnection) {
            return $this->error(404, 'invalid_request', 'No such connection.');
        } catch (TokenRejected $exception) {
            $this->log->warning('OIDC back-channel logout token refused: '.$exception->getMessage(), ['code' => $exception->errorCode()->value, 'connection' => $connection]);

            return $this->error(400, 'invalid_request', sprintf('The logout token was refused (%s).', $exception->errorCode()->value));
        } catch (SigningKeyNotFound|SigningKeyUnsuitable $exception) {
            $this->log->warning('OIDC back-channel logout token names no usable key: '.$exception->getMessage(), ['code' => $exception->errorCode()->value, 'connection' => $connection]);

            return $exception instanceof SigningKeyNotFound && $exception->retryLater()
                ? $this->error(503, 'temporarily_unavailable', sprintf('The logout token could not be verified now (%s).', $exception->errorCode()->value))
                : $this->error(400, 'invalid_request', sprintf('The logout token was refused (%s).', $exception->errorCode()->value));
        } catch (OidcException $exception) {
            $this->log->error('OIDC back-channel logout could not verify the token: '.$exception->getMessage(), ['code' => $exception->errorCode()->value, 'connection' => $connection]);

            return $this->error(503, 'temporarily_unavailable', sprintf('The logout token could not be verified now (%s).', $exception->errorCode()->value));
        }

        try {
            $this->events->dispatch(new BackChannelLogoutReceived($token));
        } catch (Throwable $exception) {
            $this->replays->release($token);

            throw $exception;
        }

        return new Response('', 200, ['Cache-Control' => 'no-store']);
    }

    private function connection(Request $request, ?string $connection): ?string
    {
        if ($connection !== null) {
            return $connection;
        }

        $route = $request->route('connection');

        return is_string($route) ? $route : null;
    }

    private function error(int $status, string $error, string $description): JsonResponse
    {
        return new JsonResponse(['error' => $error, 'error_description' => $description], $status, ['Cache-Control' => 'no-store']);
    }
}

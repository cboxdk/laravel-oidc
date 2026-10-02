<?php

declare(strict_types=1);

namespace Cbox\Oidc\Events;

use Cbox\Oidc\Logout\LogoutToken;

/**
 * The provider sent a verified logout token to the back-channel logout route:
 * end the sessions it names.
 *
 * Listen for it and end the application's sessions of $token->issuer with
 * $token->sessionId (sid), or of $token->subject when there is no sid. The
 * route answers the provider 200 once every listener has returned; a listener
 * that throws makes it answer 500, and the provider may deliver the token
 * again.
 */
final readonly class BackChannelLogoutReceived
{
    public function __construct(public LogoutToken $token) {}
}

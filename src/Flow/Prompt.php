<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

/**
 * The prompt values of an authorization request (OpenID Connect Core
 * 3.1.2.1, and create from OpenID Connect Prompt Create 1.0).
 */
enum Prompt: string
{
    /** Show no page at all; fail with login_required when the person must interact. */
    case None = 'none';

    /** Ask for the credentials again, even with a session at the provider. */
    case Login = 'login';

    /** Ask for consent again. */
    case Consent = 'consent';

    /** Let the person pick another account. */
    case SelectAccount = 'select_account';

    /** Start at the provider's sign-up page. */
    case Create = 'create';
}

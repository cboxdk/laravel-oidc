<?php

declare(strict_types=1);

namespace Cbox\Oidc\Diagnostics;

/**
 * The verdict of one check of a connection.
 */
enum CheckStatus: string
{
    /** The check passed. */
    case Pass = 'pass';

    /** Worth knowing; nothing is wrong, such as a provider without revocation. */
    case Note = 'note';

    /** Logins may work, but something is likely to cause trouble. */
    case Warn = 'warn';

    /** Logins through this connection cannot work until it is fixed. */
    case Fail = 'fail';
}

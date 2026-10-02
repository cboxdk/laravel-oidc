<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * Every error the package raises carries one of these codes. A code is stable:
 * it is never renamed, so you can match on it in logs and alerts.
 */
enum ErrorCode: string
{
    /** A value in config/oidc.php is missing or invalid. */
    case ConfigInvalid = 'oidc_config_invalid';

    /** Code asked for a connection that config/oidc.php does not define. */
    case ConnectionUnknown = 'oidc_connection_unknown';
}

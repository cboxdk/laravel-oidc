<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * Code asked for a connection name that config/oidc.php does not define.
 */
class UnknownConnection extends OidcException
{
    /**
     * @param  list<string>  $known
     */
    public static function named(string $name, array $known): self
    {
        return new self(
            ErrorCode::ConnectionUnknown,
            sprintf('There is no OIDC connection named "%s".', $name),
            $known === []
                ? 'Add it under connections in config/oidc.php.'
                : sprintf('Use one of %s, or add it under connections in config/oidc.php.', implode(', ', $known)),
        );
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Exceptions;

/**
 * The provider's discovery document does not advertise the endpoint a call
 * needs: userinfo_endpoint, end_session_endpoint or revocation_endpoint.
 *
 * Google, for example, has no end_session_endpoint. Ask the matching
 * supports...() method first, or catch this to fall back: end the session
 * locally when the provider cannot log the person out.
 */
class EndpointNotSupported extends OidcException
{
    private string $endpoint = '';

    public static function missing(string $connection, string $endpoint, string $fix): self
    {
        $exception = new self(
            ErrorCode::EndpointNotSupported,
            sprintf('The provider of connection "%s" advertises no %s.', $connection, $endpoint),
            $fix,
        );
        $exception->endpoint = $endpoint;

        return $exception;
    }

    /** The discovery member that is missing, such as end_session_endpoint. */
    public function endpoint(): string
    {
        return $this->endpoint;
    }
}

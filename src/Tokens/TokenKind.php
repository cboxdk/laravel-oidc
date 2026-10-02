<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens;

/**
 * The kinds of signed token the package verifies. Each kind decides which
 * typ header it accepts, so one kind of token is never accepted as another
 * (RFC 8725 3.11).
 */
enum TokenKind: string
{
    case IdToken = 'ID token';

    /**
     * Whether a token of this kind may carry $type as its typ header.
     *
     * An ID token has no registered explicit type: typ may be absent, JWT or
     * any other value, except an explicit type of another kind of token
     * (anything ending in +jwt, such as logout+jwt or at+jwt).
     */
    public function acceptsType(?string $type): bool
    {
        if ($type === null) {
            return true;
        }

        return ! str_ends_with(strtolower($type), '+jwt');
    }

    /** The name used in messages, such as "ID token". */
    public function label(): string
    {
        return $this->value;
    }
}

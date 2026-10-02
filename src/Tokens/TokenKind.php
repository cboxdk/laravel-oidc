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

    case LogoutToken = 'logout token';

    /** The explicit type of a logout token (OpenID Connect Back-Channel Logout 1.0, 2.4). */
    public const string LOGOUT_TYPE = 'logout+jwt';

    /**
     * Whether a token of this kind may carry $type as its typ header.
     *
     * - An ID token has no registered explicit type: typ may be absent, JWT
     *   or any other value, except an explicit type of another kind of token
     *   (anything ending in +jwt, such as logout+jwt or at+jwt).
     * - A logout token should be typed logout+jwt (also written
     *   application/logout+jwt). Providers that predate explicit typing send
     *   JWT or no typ; those are accepted too, because the events claim and
     *   the ban on nonce already keep an ID token from passing as one. Any
     *   other type is refused.
     */
    public function acceptsType(?string $type): bool
    {
        if ($type === null) {
            return true;
        }

        $type = strtolower($type);

        return match ($this) {
            self::IdToken => ! str_ends_with($type, '+jwt'),
            self::LogoutToken => in_array($type, ['jwt', self::LOGOUT_TYPE, 'application/'.self::LOGOUT_TYPE], true),
        };
    }

    /** The name used in messages, such as "ID token". */
    public function label(): string
    {
        return $this->value;
    }
}

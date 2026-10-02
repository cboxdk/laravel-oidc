<?php

declare(strict_types=1);

namespace Cbox\Oidc\Tokens\Concerns;

/**
 * The standard claims about the person (OpenID Connect Core 5.1) that most
 * applications read, for VerifiedClaims and UserInfo. Builds on
 * {@see ReadsClaims}.
 */
trait ReadsPersonClaims
{
    use ReadsClaims;

    /**
     * The email claim. Use it to contact the person, not to identify them:
     * check {@see self::emailVerified()} before you trust it, and match
     * accounts on issuer and subject.
     */
    public function email(): ?string
    {
        return $this->string('email');
    }

    /** Whether the provider says it verified the email address: true only for the JSON value true. */
    public function emailVerified(): bool
    {
        return $this->bool('email_verified') === true;
    }

    /** The name claim, the person's full name for display. */
    public function name(): ?string
    {
        return $this->string('name');
    }
}

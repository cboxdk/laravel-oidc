<?php

declare(strict_types=1);

namespace Cbox\Oidc\Logout;

use Cbox\Oidc\Exceptions\InvalidLogoutOptions;
use Cbox\Oidc\Support\Url;
use SensitiveParameter;

/**
 * Options for an RP-initiated logout (OpenID Connect RP-Initiated Logout
 * 1.0, 2):
 *
 * ```php
 * new LogoutOptions(idTokenHint: $idToken, state: $state);
 * ```
 *
 * - $idTokenHint: the ID token the person signed in with. Recommended: with
 *   it the provider knows whose session to end and may skip asking.
 * - $postLogoutRedirectUri: where the provider sends the browser back;
 *   replaces the connection's post_logout_redirect_uri. Must be registered
 *   at the provider.
 * - $state: sent as state and returned on the redirect back.
 * - $logoutHint: sent as logout_hint, such as the account's email address.
 * - $uiLocales: sent as ui_locales, in order of preference.
 *
 * Every value is checked here, so a wrong option fails where it is written.
 */
final readonly class LogoutOptions
{
    /**
     * @param  list<string>  $uiLocales
     *
     * @throws InvalidLogoutOptions
     */
    public function __construct(
        #[SensitiveParameter] public ?string $idTokenHint = null,
        public ?string $postLogoutRedirectUri = null,
        public ?string $state = null,
        public ?string $logoutHint = null,
        public array $uiLocales = [],
    ) {
        if ($idTokenHint !== null && (strlen($idTokenHint) > 16384 || preg_match('/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/D', $idTokenHint) !== 1)) {
            throw InvalidLogoutOptions::option('idTokenHint', 'is not a compact JWT', 'Pass the ID token exactly as the token endpoint returned it ($result->tokens->idToken), or null.');
        }

        if ($postLogoutRedirectUri !== null && ! $this->browserUrl($postLogoutRedirectUri)) {
            throw InvalidLogoutOptions::option('postLogoutRedirectUri', 'is not an absolute https URL (http only on a local host) without user info or a fragment', 'Pass the full URL registered at the provider, or null to use the connection\'s post_logout_redirect_uri.');
        }

        if ($state !== null && preg_match('/^[\x20-\x7E]{1,512}$/D', $state) !== 1) {
            throw InvalidLogoutOptions::option('state', 'is not 1 to 512 printable ASCII characters', 'Pass an opaque value, such as a random string you keep in the session, or null.');
        }

        if ($logoutHint !== null && preg_match('/^[^\x00-\x1F\x7F]{1,255}$/Du', $logoutHint) !== 1) {
            throw InvalidLogoutOptions::option('logoutHint', 'is not 1 to 255 printable characters', 'Pass the email address or user name of the account, or null.');
        }

        foreach ($uiLocales as $locale) {
            // BCP 47 language tags.
            if (preg_match('/^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$/D', $locale) !== 1) {
                throw InvalidLogoutOptions::option('uiLocales', sprintf('has "%s", which is not a language tag', (string) preg_replace('/[^\x20-\x7E]/', '?', substr($locale, 0, 32))), 'Pass BCP 47 language tags such as en or da-DK.');
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'idTokenHint' => $this->idTokenHint === null ? null : '[redacted]',
            'postLogoutRedirectUri' => $this->postLogoutRedirectUri,
            'state' => $this->state,
            'logoutHint' => $this->logoutHint,
            'uiLocales' => $this->uiLocales,
        ];
    }

    private function browserUrl(string $url): bool
    {
        $parts = parse_url($url);

        $scheme = strtolower($parts['scheme'] ?? '');

        return is_array($parts)
            && ($parts['host'] ?? '') !== ''
            && ($scheme === 'https' || ($scheme === 'http' && Url::isLocalHost($parts['host'])))
            && ! isset($parts['user'])
            && ! isset($parts['pass'])
            && ! isset($parts['fragment']);
    }
}

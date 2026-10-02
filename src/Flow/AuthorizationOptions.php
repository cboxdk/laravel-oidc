<?php

declare(strict_types=1);

namespace Cbox\Oidc\Flow;

use Cbox\Oidc\Config\ConnectionConfig;
use Cbox\Oidc\Exceptions\InvalidAuthorizationOptions;

/**
 * Per-login options for the authorization request, on top of what the
 * connection configures:
 *
 * ```php
 * new AuthorizationOptions(prompt: Prompt::Login, maxAge: 0, loginHint: 'ada@example.com');
 * ```
 *
 * - $prompt: one or more {@see Prompt}s; none must stand alone.
 * - $maxAge: replaces the connection's max_age for this login. The ID token
 *   must then carry an auth_time no older than this.
 * - $loginHint: sent as login_hint, such as an email address.
 * - $scopes: added to the connection's scopes.
 * - $acrValues: sent as acr_values, in order of preference.
 * - $parameters: other parameters, such as ui_locales or domain_hint. They
 *   replace the connection's authorization_parameters of the same name.
 *   Parameters the package sets itself are refused.
 *
 * Every value is checked here, so a wrong option fails where it is written.
 */
final readonly class AuthorizationOptions
{
    /** Parameters with their own option, which $parameters may not set. */
    public const array OPTION_PARAMETERS = ['acr_values', 'login_hint', 'prompt'];

    /** @var list<Prompt> */
    public array $prompts;

    /**
     * @param  Prompt|list<Prompt>|null  $prompt
     * @param  list<string>  $scopes
     * @param  list<string>  $acrValues
     * @param  array<string, string>  $parameters
     *
     * @throws InvalidAuthorizationOptions
     */
    public function __construct(
        Prompt|array|null $prompt = null,
        public ?int $maxAge = null,
        public ?string $loginHint = null,
        public array $scopes = [],
        public array $acrValues = [],
        public array $parameters = [],
    ) {
        $this->prompts = $this->prompts($prompt);

        if ($maxAge !== null && ($maxAge < 0 || $maxAge > 31536000)) {
            throw InvalidAuthorizationOptions::because('maxAge must be from 0 to 31536000 seconds', 'Pass the most seconds since the person last signed in at the provider, or null to use the connection\'s max_age.');
        }

        if ($loginHint !== null && preg_match('/^[^\x00-\x1F\x7F]{1,255}$/Du', $loginHint) !== 1) {
            throw InvalidAuthorizationOptions::because('loginHint must be 1 to 255 printable characters', 'Pass the email address or user name the person typed, or null.');
        }

        foreach ([...$scopes, ...$acrValues] as $value) {
            // RFC 6749 3.3 scope-token; acr values share the form.
            if (preg_match('/^[\x21\x23-\x5B\x5D-\x7E]{1,255}$/D', $value) !== 1) {
                throw InvalidAuthorizationOptions::because(sprintf('"%s" is not a valid scope or acr value', $this->printable($value)), 'Use printable ASCII without spaces, quotes or backslashes.');
            }
        }

        foreach ($parameters as $name => $value) {
            $lower = strtolower($name);

            if (preg_match('/^[A-Za-z0-9_.-]{1,64}$/D', $name) !== 1) {
                throw InvalidAuthorizationOptions::because(sprintf('"%s" is not a valid parameter name', $this->printable($name)), 'Use letters, digits, dots, dashes and underscores.');
            }

            if (in_array($lower, ConnectionConfig::RESERVED_PARAMETERS, true) || in_array($lower, self::OPTION_PARAMETERS, true)) {
                throw InvalidAuthorizationOptions::because(sprintf('the parameter %s is set by the package itself or has its own option', $name), 'Use the prompt, maxAge, loginHint, scopes or acrValues option instead, or leave it to the package.');
            }

            if (strlen($value) > 2048) {
                throw InvalidAuthorizationOptions::because(sprintf('the value of %s is longer than 2048 bytes', $name), 'Keep authorization parameters short; they travel in the URL.');
            }
        }
    }

    /**
     * @param  Prompt|list<Prompt>|null  $prompt
     * @return list<Prompt>
     */
    private function prompts(Prompt|array|null $prompt): array
    {
        $prompts = match (true) {
            $prompt === null => [],
            $prompt instanceof Prompt => [$prompt],
            default => $prompt,
        };

        if (count(array_unique(array_map(static fn (Prompt $value): string => $value->value, $prompts))) !== count($prompts)) {
            throw InvalidAuthorizationOptions::because('a prompt value is given twice', 'Pass each prompt value once.');
        }

        if (count($prompts) > 1 && in_array(Prompt::None, $prompts, true)) {
            throw InvalidAuthorizationOptions::because('prompt none is combined with another prompt', 'Pass Prompt::None alone for a silent login (OpenID Connect Core 3.1.2.1).');
        }

        return $prompts;
    }

    private function printable(string $value): string
    {
        $value = (string) preg_replace('/[^\x20-\x7E]/', '?', $value);

        return strlen($value) > 64 ? substr($value, 0, 64).'...' : $value;
    }
}

<?php

declare(strict_types=1);

namespace Cbox\Oidc\Http;

use SensitiveParameter;

/**
 * One call to a provider. Form fields and headers can carry secrets (the
 * client secret, an authorization code, a refresh token), so a dump shows
 * their names only.
 */
final readonly class HttpRequest
{
    /**
     * @param  array<string, string>  $headers
     * @param  array<string, string>  $form
     */
    private function __construct(
        public HttpMethod $method,
        public string $url,
        #[SensitiveParameter] public array $headers,
        #[SensitiveParameter] public array $form,
    ) {}

    /**
     * @param  array<string, string>  $headers
     */
    public static function get(string $url, array $headers = []): self
    {
        return new self(HttpMethod::Get, $url, $headers, []);
    }

    /**
     * An application/x-www-form-urlencoded POST, as the token, revocation and
     * userinfo endpoints take it.
     *
     * @param  array<string, string>  $form
     * @param  array<string, string>  $headers
     */
    public static function postForm(string $url, #[SensitiveParameter] array $form, #[SensitiveParameter] array $headers = []): self
    {
        return new self(HttpMethod::Post, $url, $headers, $form);
    }

    /**
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'method' => $this->method,
            'url' => $this->url,
            'headers' => array_keys($this->headers),
            'form' => array_keys($this->form),
        ];
    }
}

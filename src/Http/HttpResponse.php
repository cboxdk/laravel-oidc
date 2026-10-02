<?php

declare(strict_types=1);

namespace Cbox\Oidc\Http;

/**
 * A provider's answer: the status, the headers (names in lower case, repeated
 * headers joined with ", ") and the body, already capped in size.
 */
final readonly class HttpResponse
{
    /**
     * @param  array<string, string>  $headers
     */
    public function __construct(
        public int $status,
        public array $headers,
        public string $body,
    ) {}

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    public function successful(): bool
    {
        return $this->status >= 200 && $this->status < 300;
    }

    /**
     * A status that says "try again later" rather than "this is wrong":
     * 408, 429 and the 5xx range.
     */
    public function temporaryFailure(): bool
    {
        return $this->status === 408 || $this->status === 429 || $this->status >= 500;
    }
}
